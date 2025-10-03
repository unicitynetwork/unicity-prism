//! TCP connection management for Alpha P2P protocol.
//!
//! This module provides functionality for establishing and maintaining TCP
//! connections to Alpha peers, with support for timeouts, message sending, and
//! receiving.

use std::{io, net::SocketAddr, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tracing::{debug, error, info};

use crate::{
    client::{
        Message,
        message::MessageCommand,
        network::{NetworkError, NetworkMessage, NetworkMessageHeader},
    },
    consensus::Decodable,
    hashes::ChecksumHash,
    network::Network,
    p2p::Magic,
};

/// Errors that can occur during connection management.
#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    /// IO error during connection operations.
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// Network protocol error.
    #[error("Network error: {0}")]
    Network(#[from] NetworkError),

    /// Connection timeout.
    #[error("Connection timeout after {0:?}")]
    Timeout(Duration),

    /// Connection closed by peer.
    #[error("Connection closed by peer")]
    ConnectionClosed,

    /// Invalid message format.
    #[error("Invalid message format: {0}")]
    InvalidMessage(String),
}

/// Configuration for connection management.
#[derive(Debug, Clone, Copy)]
pub struct ConnectionConfig {
    /// Network type (mainnet, testnet, regtest).
    pub network: Network,
    /// Connection timeout.
    pub connect_timeout: Duration,
    /// Read timeout for receiving messages.
    pub read_timeout: Duration,
    /// Write timeout for sending messages.
    pub write_timeout: Duration,
    /// Maximum message size.
    pub max_message_size: u32,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            network: Network::Testnet,
            connect_timeout: Duration::from_secs(30),
            read_timeout: Duration::from_secs(60),
            write_timeout: Duration::from_secs(30),
            max_message_size:
                NetworkMessage::<crate::blockdata::block::BitcoinHeader>::MAX_PAYLOAD_SIZE,
        }
    }
}

/// Manages TCP connections to Bitcoin peers.
#[derive(Debug, Clone, Copy)]
pub struct ConnectionManager {
    config: ConnectionConfig,
    magic: Magic,
}

impl ConnectionManager {
    /// Creates a new connection manager with the given configuration.
    pub fn new(config: ConnectionConfig) -> Self {
        let magic = Magic::from(config.network);
        Self { config, magic }
    }

    /// Creates a new connection manager for the specified network.
    pub fn for_network(network: Network) -> Self {
        let config = ConnectionConfig {
            network,
            ..Default::default()
        };
        Self::new(config)
    }

    /// Establishes a TCP connection to the specified peer address.
    pub async fn connect(&self, addr: SocketAddr) -> Result<TcpStream, ConnectionError> {
        info!("Connecting to peer: {}", addr);

        let stream = timeout(self.config.connect_timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| ConnectionError::Timeout(self.config.connect_timeout))?
            .map_err(ConnectionError::Io)?;

        info!("Successfully connected to peer: {}", addr);
        Ok(stream)
    }

    /// Sends a message to the peer through the given TCP stream.
    pub async fn send_message<H>(
        &self,
        stream: &mut TcpStream,
        message: Message<H>,
    ) -> Result<(), ConnectionError>
    where
        H: crate::blockdata::block::Header,
    {
        // Create network message
        let network_msg = NetworkMessage::new(self.magic, message)?;

        // Serialize to bytes
        let bytes = network_msg.to_bytes()?;

        debug!(
            "Sending {} message: {} bytes",
            network_msg.header.command,
            bytes.len()
        );

        // Send with timeout
        match timeout(self.config.write_timeout, stream.write_all(&bytes)).await {
            Ok(Ok(_)) => {
                info!("{} message sent successfully", network_msg.header.command);
            }
            Ok(Err(e)) => {
                error!("Failed to send message: {}", e);
                return Err(ConnectionError::Io(e));
            }
            Err(_) => {
                error!("Send message timeout after {:?}", self.config.write_timeout);
                return Err(ConnectionError::Timeout(self.config.write_timeout));
            }
        }

        // Flush the stream to ensure the message is sent immediately
        match timeout(self.config.write_timeout, stream.flush()).await {
            Ok(Ok(_)) => {
                debug!("Stream flushed successfully");
            }
            Ok(Err(e)) => {
                error!("Failed to flush stream: {}", e);
                return Err(ConnectionError::Io(e));
            }
            Err(_) => {
                error!("Flush stream timeout after {:?}", self.config.write_timeout);
                return Err(ConnectionError::Timeout(self.config.write_timeout));
            }
        }

        Ok(())
    }

    /// Receives a message from the peer through the given TCP stream.
    pub async fn receive_message<H>(
        &self,
        stream: &mut TcpStream,
    ) -> Result<Message<H>, ConnectionError>
    where
        H: crate::blockdata::block::Header,
    {
        debug!("Waiting to receive message header...");
        let mut temp_buffer = vec![0u8; NetworkMessageHeader::SIZE];
        let short_timeout = Duration::from_secs(5);
        match timeout(short_timeout, stream.read(&mut temp_buffer)).await {
            Ok(Ok(0)) => {
                debug!("Peer closed connection during short timeout read");
                return Err(ConnectionError::ConnectionClosed);
            }
            Ok(Ok(n)) if n > 0 => {
                return if n == NetworkMessageHeader::SIZE {
                    let header_bytes = temp_buffer;
                    // Continue with processing the header
                    self.process_header(header_bytes, stream).await
                } else {
                    match timeout(
                        self.config.read_timeout,
                        stream.read_exact(temp_buffer.get_mut(n..).ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidInput, "Invalid buffer slice")
                        })?),
                    )
                    .await
                    {
                        Ok(Ok(_)) => {
                            let header_bytes = temp_buffer;
                            self.process_header(header_bytes, stream).await
                        }
                        Ok(Err(e)) => {
                            error!("Error getting rest of header: {}", e);
                            Err(ConnectionError::Io(e))
                        }
                        Err(_) => {
                            error!("Timeout while getting rest of header");
                            Err(ConnectionError::Timeout(self.config.read_timeout))
                        }
                    }
                };
            }
            Ok(Ok(_)) => {
                debug!("No data received during short timeout read");
                // No data during short timeout read, will try with full timeout
            }
            Ok(Err(e)) => {
                error!("Error during short timeout read: {}", e);
                return Err(ConnectionError::Io(e));
            }
            Err(e) => {
                error!("Timeout during short timeout read: {:?}", e);
                // Short timeout elapsed, will try with full timeout
            }
        }

        // Read message header with full timeout
        let header_bytes = timeout(
            self.config.read_timeout,
            self.read_exact(stream, NetworkMessageHeader::SIZE),
        )
        .await
        .map_err(|e| {
            error!("Timeout or error while receiving message header: {:?}", e);
            ConnectionError::Timeout(self.config.read_timeout)
        })??;

        let payload_bytes = self
            .validate_and_read_payload(stream, &header_bytes)
            .await?;
        self.parse_and_validate_message(&header_bytes, payload_bytes)
            .await
    }

    /// Deserializes a message payload based on the command string.
    fn deserialize_payload<H>(
        &self,
        command: &bitcoin::p2p::message::CommandString,
        payload: &[u8],
    ) -> Result<Message<H>, ConnectionError>
    where
        H: crate::blockdata::block::Header,
    {
        let mut cursor = io::Cursor::new(payload);
        MessageCommand::parse_and_decode(command, &mut cursor).map_err(ConnectionError::Network)
    }

    /// Processes a message header that has already been read.
    async fn process_header<H>(
        &self,
        header_bytes: Vec<u8>,
        stream: &mut TcpStream,
    ) -> Result<Message<H>, ConnectionError>
    where
        H: crate::blockdata::block::Header,
    {
        let payload_bytes = self
            .validate_and_read_payload(stream, &header_bytes)
            .await?;
        self.parse_and_validate_message(&header_bytes, payload_bytes)
            .await
    }

    /// Reads exactly the specified number of bytes from the stream.
    async fn read_exact(
        &self,
        stream: &mut TcpStream,
        len: usize,
    ) -> Result<Vec<u8>, ConnectionError> {
        let mut buffer = vec![0u8; len];
        let mut bytes_read = 0;

        let mut attempts: u32 = 0;
        while bytes_read < len {
            attempts = attempts.saturating_add(1);
            let n = timeout(
                self.config.read_timeout,
                stream.read(buffer.get_mut(bytes_read..).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "Invalid buffer slice")
                })?),
            )
            .await
            .map_err(|e| {
                error!(
                    "Read timeout or error after {} bytes and {} attempts: {:?}",
                    bytes_read, attempts, e
                );
                ConnectionError::Timeout(self.config.read_timeout)
            })??;

            if n == 0 {
                error!(
                    "Connection closed by peer after {} bytes and {} attempts",
                    bytes_read, attempts
                );
                return Err(ConnectionError::ConnectionClosed);
            }

            bytes_read = bytes_read.saturating_add(n);

            // If we've read some bytes but not all, add a small delay to allow more data to
            // arrive
            if bytes_read < len && bytes_read > 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
        Ok(buffer)
    }

    /// Validates the message header and reads the payload from the stream
    async fn validate_and_read_payload(
        &self,
        stream: &mut TcpStream,
        header_bytes: &[u8],
    ) -> Result<Vec<u8>, ConnectionError> {
        // Parse header
        let header = NetworkMessageHeader::consensus_decode(&mut io::Cursor::new(header_bytes))
            .map_err(NetworkError::Consensus)?;

        debug!(
            "Received {} message header: {} bytes",
            header.command, header.length
        );

        // Validate magic bytes
        self.validate_magic_bytes(&header)?;

        // Check payload size
        self.validate_payload_size(&header)?;

        // Read payload
        let payload_size = usize::try_from(header.length).unwrap_or(0);
        debug!("Reading {} payload: {} bytes", header.command, payload_size);

        let payload_bytes = if payload_size > 0 {
            timeout(
                self.config.read_timeout,
                self.read_exact(stream, payload_size),
            )
            .await
            .map_err(|_| ConnectionError::Timeout(self.config.read_timeout))??
        } else {
            Vec::new()
        };

        Ok(payload_bytes)
    }

    /// Parses and validates a message with its payload
    async fn parse_and_validate_message<H>(
        &self,
        header_bytes: &[u8],
        payload_bytes: Vec<u8>,
    ) -> Result<Message<H>, ConnectionError>
    where
        H: crate::blockdata::block::Header,
    {
        // Parse header
        let header = NetworkMessageHeader::consensus_decode(&mut io::Cursor::new(header_bytes))
            .map_err(NetworkError::Consensus)?;

        // Validate checksum
        self.validate_checksum(&header, &payload_bytes)?;

        // Deserialize payload based on command
        let payload = self.deserialize_payload(&header.command, &payload_bytes)?;

        let payload_size = payload_bytes.len();
        info!(
            "Successfully parsed {} message: {} bytes",
            header.command, payload_size
        );
        Ok(payload)
    }

    /// Validates the magic bytes in the message header
    fn validate_magic_bytes(&self, header: &NetworkMessageHeader) -> Result<(), ConnectionError> {
        if header.magic != self.magic {
            error!(
                "Invalid magic bytes: expected {:02x?}, got {:02x?}",
                u32::from_le_bytes(self.magic.to_bytes()),
                u32::from_le_bytes(header.magic.to_bytes())
            );
            return Err(ConnectionError::Network(NetworkError::InvalidMagic {
                expected: u32::from_le_bytes(self.magic.to_bytes()),
                actual: u32::from_le_bytes(header.magic.to_bytes()),
            }));
        }
        Ok(())
    }

    /// Validates the payload size in the message header
    fn validate_payload_size(&self, header: &NetworkMessageHeader) -> Result<(), ConnectionError> {
        if header.length > self.config.max_message_size {
            error!(
                "Payload too large: {} bytes (max: {} bytes)",
                header.length, self.config.max_message_size
            );
            return Err(ConnectionError::Network(NetworkError::PayloadTooLarge {
                size: header.length,
                max: self.config.max_message_size,
            }));
        }
        Ok(())
    }

    /// Validates the checksum of the payload
    fn validate_checksum(
        &self,
        header: &NetworkMessageHeader,
        payload_bytes: &[u8],
    ) -> Result<(), ConnectionError> {
        let checksum_hash = ChecksumHash::hash(payload_bytes);
        let expected_checksum = checksum_hash.checksum();

        if header.checksum != expected_checksum {
            error!(
                "Invalid checksum: expected {:02x?}, got {:02x?}",
                u32::from_le_bytes(expected_checksum),
                u32::from_le_bytes(header.checksum)
            );
            return Err(ConnectionError::Network(NetworkError::InvalidChecksum {
                expected: u32::from_le_bytes(expected_checksum),
                actual: u32::from_le_bytes(header.checksum),
            }));
        }
        Ok(())
    }

    /// Gets the network magic bytes for this connection.
    pub fn magic(&self) -> Magic {
        self.magic
    }

    /// Gets the network type for this connection.
    pub fn network(&self) -> Network {
        self.config.network
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::{
        blockdata::block::BitcoinHeader,
        client::message::{Connection, Message, connection::Version},
        p2p::address::AddrV2,
    };

    #[tokio::test]
    async fn test_connection_manager_creation() {
        let config = ConnectionConfig::default();
        let manager = ConnectionManager::new(config);

        assert_eq!(manager.network(), Network::Testnet);
    }

    #[tokio::test]
    async fn test_message_serialization() {
        let manager = ConnectionManager::for_network(Network::Testnet);

        // Create a test version message
        let addr_recv = AddrV2::Ipv4(Ipv4Addr::new(127, 0, 0, 1));
        let addr_from = AddrV2::Ipv4(Ipv4Addr::new(127, 0, 0, 1));
        let version = Version::new(addr_recv, addr_from, "test".to_string(), 0);
        let message = Message::<BitcoinHeader>::Connection(Connection::Version(version));

        // Test network message creation
        let network_msg = NetworkMessage::new(manager.magic(), message.clone());
        assert!(network_msg.is_ok());

        let network_msg = network_msg.unwrap();
        let bytes = network_msg.to_bytes();
        assert!(bytes.is_ok());

        let bytes = bytes.unwrap();
        assert!(!bytes.is_empty());
    }

    #[tokio::test]
    async fn test_timeout_configuration() {
        let mut config = ConnectionConfig::default();
        config.connect_timeout = Duration::from_secs(5);
        config.read_timeout = Duration::from_secs(10);
        config.write_timeout = Duration::from_secs(7);

        let manager = ConnectionManager::new(config);

        // These values should be used in timeout operations
        assert_eq!(manager.config.connect_timeout, Duration::from_secs(5));
        assert_eq!(manager.config.read_timeout, Duration::from_secs(10));
        assert_eq!(manager.config.write_timeout, Duration::from_secs(7));
    }
}
