//! Handshake protocol implementation for Bitcoin P2P connections.
//!
//! This module provides functionality for performing the Bitcoin P2P handshake
//! protocol, which involves exchanging Version and VerAck messages to establish
//! a connection with a peer.

use std::net::{IpAddr, SocketAddr};

use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::alpha::{
    blockdata::block::Header,
    client::{
        connection::{ConnectionError, ConnectionManager},
        message::{Connection, Message, connection::Version},
    },
    p2p::{ServiceFlags, address::AddrV2},
};

/// Information about a peer after successful handshake.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// The socket address of the peer.
    pub addr: SocketAddr,
    /// The protocol version used by the peer.
    pub version: i32,
    /// The services offered by the peer.
    pub services: ServiceFlags,
    /// The timestamp from the peer's version message.
    pub timestamp: i64,
    /// The user agent string of the peer.
    pub user_agent: String,
    /// The best block height known to the peer.
    pub best_height: i32,
    /// Whether the peer relays transactions.
    pub relay: bool,
}

/// Handshake state machine.
#[derive(Debug, Clone, PartialEq)]
enum HandshakeState {
    /// Initial state before any messages are exchanged.
    #[allow(dead_code)]
    Init,
    /// Version message sent, waiting for peer's version.
    VersionSent,
    /// Both version messages exchanged, waiting for peer's verack.
    VersionExchanged,
    /// VerAck sent, waiting for peer's verack.
    #[allow(dead_code)]
    VerAckSent,
    /// Handshake completed successfully.
    Completed,
}

/// Handles the Bitcoin P2P handshake protocol.
#[derive(Debug)]
pub struct HandshakeHandler {
    user_agent: String,
    start_height: i32,
    services: ServiceFlags,
}

impl HandshakeHandler {
    /// Creates a new handshake handler with the given parameters.
    pub fn new(user_agent: String, start_height: i32) -> Self {
        Self {
            user_agent,
            start_height,
            services: ServiceFlags::NONE,
        }
    }

    /// Sets the services flags to advertise in the version message.
    pub fn with_services(mut self, services: ServiceFlags) -> Self {
        debug!(
            "Setting handshake handler services to: {:?} (raw: {:x})",
            services,
            services.to_u64()
        );
        self.services = services;
        debug!(
            "Handshake handler services set to: {:?} (raw: {:x})",
            self.services,
            self.services.to_u64()
        );
        self
    }

    /// Performs the complete handshake with a peer.
    pub async fn perform_handshake<H: Header + std::fmt::Debug>(
        &self,
        connection: &ConnectionManager,
        stream: &mut TcpStream,
        peer_addr: SocketAddr,
    ) -> Result<PeerInfo, ConnectionError> {
        info!("Starting handshake with peer: {}", peer_addr);

        let mut peer_info = None;
        let mut state = HandshakeState::VersionSent; // Initialize state after sending version

        // Send our version message
        let version_msg = self.create_version_message(peer_addr)?;
        debug!(
            "Created version message: version={}, services={}, user_agent={}, start_height={}, \
             nonce={}",
            version_msg.version(),
            version_msg.services(),
            version_msg.user_agent(),
            version_msg.start_height(),
            version_msg.nonce()
        );

        connection
            .send_message(
                stream,
                Message::<H>::Connection(Connection::Version(version_msg.clone())),
            )
            .await?;
        debug!("Sent version message to peer: {}", peer_addr);

        // Perform message exchange loop
        while state != HandshakeState::Completed {
            debug!(
                "Handshake state: {:?}, waiting for message from peer: {}",
                state, peer_addr
            );
            let message: Message<H> = connection.receive_message(stream).await?;

            state = match (state, message) {
                (
                    HandshakeState::VersionSent,
                    Message::Connection(Connection::Version(peer_version)),
                ) => {
                    info!("Received version message from peer: {}", peer_addr);
                    debug!(
                        "Peer version details: version={}, services={}, user_agent={}, \
                         start_height={}, relay={}",
                        peer_version.version(),
                        peer_version.services(),
                        peer_version.user_agent(),
                        peer_version.start_height(),
                        peer_version.relay()
                    );

                    // Store peer information
                    peer_info = Some(PeerInfo {
                        addr: peer_addr,
                        version: peer_version.version(),
                        services: peer_version.services(),
                        timestamp: peer_version.timestamp(),
                        user_agent: peer_version.user_agent().to_string(),
                        best_height: peer_version.start_height(),
                        relay: peer_version.relay(),
                    });

                    // Send our verack
                    debug!("Created verack message");
                    connection
                        .send_message(stream, Message::<H>::Connection(Connection::VerAck))
                        .await?;
                    debug!("Sent verack message to peer: {}", peer_addr);

                    HandshakeState::VersionExchanged
                }

                (HandshakeState::VersionExchanged, Message::Connection(Connection::WtxIdRelay)) => {
                    info!("Received wtxidrelay message from peer: {}", peer_addr);
                    debug!("Peer supports wtxid-based transaction relay (BIP 339)");
                    // Stay in the same state, wait for verack
                    HandshakeState::VersionExchanged
                }

                (HandshakeState::VersionExchanged, Message::Connection(Connection::SendAddrV2)) => {
                    info!("Received sendaddrv2 message from peer: {}", peer_addr);
                    debug!("Peer supports addrv2 format (BIP 155)");
                    debug!(
                        "Handshake state after sendaddrv2: VersionExchanged, waiting for verack"
                    );
                    // Stay in the same state, wait for verack
                    HandshakeState::VersionExchanged
                }

                (HandshakeState::VersionExchanged, Message::Connection(Connection::VerAck)) => {
                    info!("Received verack message from peer: {}", peer_addr);
                    HandshakeState::Completed
                }

                // Handle unexpected messages
                (state, msg) => {
                    warn!(
                        "Received unexpected message during handshake (state: {:?}): {:?}",
                        state, msg
                    );
                    state
                }
            };
        }

        info!("Handshake completed successfully with peer: {}", peer_addr);

        // Return peer information
        peer_info.ok_or_else(|| {
            ConnectionError::InvalidMessage(
                "Handshake completed but no peer info was collected".to_string(),
            )
        })
    }

    /// Creates a version message for the handshake.
    fn create_version_message(&self, peer_addr: SocketAddr) -> Result<Version, ConnectionError> {
        // Create address for receiving node (peer)
        let addr_recv = match peer_addr.ip() {
            IpAddr::V4(ip) => AddrV2::Ipv4(ip),
            IpAddr::V6(ip) => AddrV2::Ipv6(ip),
        };

        // Create address for sending node (us)
        // We use 0.0.0.0:0 as a placeholder since we don't know our external IP
        let addr_from = AddrV2::Ipv4(std::net::Ipv4Addr::UNSPECIFIED);

        // Create version message
        let version = Version::new(
            addr_recv,
            addr_from,
            self.user_agent.clone(),
            self.start_height,
        );

        Ok(version)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;

    #[test]
    fn test_handshake_handler_creation() {
        let user_agent = "/test:0.1.0/".to_string();
        let start_height = 0;

        let handler = HandshakeHandler::new(user_agent.clone(), start_height);

        assert_eq!(handler.user_agent, user_agent);
        assert_eq!(handler.start_height, start_height);
    }

    #[test]
    fn test_handshake_state_transitions() {
        assert_eq!(HandshakeState::Init, HandshakeState::Init);
        assert_ne!(HandshakeState::Init, HandshakeState::VersionSent);
        assert_ne!(
            HandshakeState::VersionSent,
            HandshakeState::VersionExchanged
        );
        assert_ne!(HandshakeState::VersionExchanged, HandshakeState::VerAckSent);
        assert_ne!(HandshakeState::VerAckSent, HandshakeState::Completed);
    }

    #[test]
    fn test_peer_info_creation() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8333);
        let peer_info = PeerInfo {
            addr,
            version: 70015,
            services: ServiceFlags::NONE,
            timestamp: 1234567890,
            user_agent: "/test:0.1.0/".to_string(),
            best_height: 100,
            relay: false,
        };

        assert_eq!(peer_info.addr, addr);
        assert_eq!(peer_info.version, 70015);
        assert_eq!(peer_info.best_height, 100);
        assert!(!peer_info.relay);
    }

    #[test]
    fn test_version_message_creation() {
        let user_agent = "/test:0.1.0/".to_string();
        let start_height = 0;
        let handler = HandshakeHandler::new(user_agent, start_height);

        let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8333);
        let version_msg = handler
            .create_version_message(peer_addr)
            .expect("Failed to create version message");

        assert_eq!(version_msg.version(), 70016); // Default protocol version
        assert_eq!(version_msg.start_height(), 0);
        assert_eq!(version_msg.user_agent(), "/test:0.1.0/");
    }
}
