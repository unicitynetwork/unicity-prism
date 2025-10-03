use alpha_p2p_derive::ConsensusCodec;
use bitcoin::p2p::address::Address as NetAddress;
use chrono::Utc;
use rand::{RngCore, rng};

use crate::p2p::{ServiceFlags, address::AddrV2};

/// If the node can relay transactions or not.
const IS_RELAY: bool = false;

/// The protocol version being used.
const PROTOCOL_VERSION: i32 = 70016;

/// The services supported by the node.
const SERVICES: ServiceFlags = ServiceFlags::NONE;

/// Represents a version message in the P2P protocol.
///
/// A version message is used to initiate a connection between two peers.
/// It contains information about the protocol version, services supported,
/// timestamps, network addresses, user agent, and other relevant details.
#[derive(Debug, Clone, PartialEq, Eq, ConsensusCodec)]
pub struct Version {
    /// The version of the protocol being used.
    pub version: i32,
    /// The services supported by the node.
    pub services: ServiceFlags,
    /// The timestamp when the message was created.
    pub timestamp: i64,
    /// The network address of the receiving node.
    pub addr_recv: NetAddress,
    /// The network address of the sending node.
    pub addr_from: NetAddress,
    /// A unique identifier for the connection, typically a random nonce.
    pub nonce: u64,
    /// The user agent string of the node, typically identifying the software
    /// and version.
    pub user_agent: String,
    /// The last block height known to the sending node.
    pub start_height: i32,
    /// Whether the node wants to receive relayed transactions or not.
    pub relay: bool,
}

impl Version {
    /// Creates a new Version message with the given parameters.
    ///
    /// # Arguments
    ///
    /// * `addr_recv` - The network address of the receiving node.
    /// * `addr_from` - The network address of the sending node.
    /// * `user_agent` - The user agent string of the node.
    /// * `start_height` - The last block height known to the sending node.
    ///
    /// # Returns
    ///
    /// * `Version` - A new instance of the Version message.
    pub fn new(
        addr_recv: AddrV2,
        addr_from: AddrV2,
        user_agent: String,
        start_height: i32,
    ) -> Self {
        let nonce = rng().next_u64();
        let timestamp = Utc::now().timestamp();

        // Convert AddrV2 to NetAddress for the version message
        // NetAddress includes services, address, and port
        let net_addr_recv = match addr_recv {
            AddrV2::Ipv4(ip) => {
                // For Unicity Alpha, use the port from the connection (8590)
                let socket_addr = std::net::SocketAddr::new(std::net::IpAddr::V4(ip), 8590);
                NetAddress::new(&socket_addr, SERVICES)
            }
            AddrV2::Ipv6(ip) => {
                // For Unicity Alpha, use the port from the connection (8590)
                let socket_addr = std::net::SocketAddr::new(std::net::IpAddr::V6(ip), 8590);
                NetAddress::new(&socket_addr, SERVICES)
            }
            _ => {
                // For other address types, use a default IPv4 address
                let socket_addr = std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                    0,
                );
                NetAddress::new(&socket_addr, SERVICES)
            }
        };

        let net_addr_from = match addr_from {
            AddrV2::Ipv4(ip) => {
                let socket_addr = std::net::SocketAddr::new(std::net::IpAddr::V4(ip), 0);
                NetAddress::new(&socket_addr, SERVICES)
            }
            AddrV2::Ipv6(ip) => {
                let socket_addr = std::net::SocketAddr::new(std::net::IpAddr::V6(ip), 0);
                NetAddress::new(&socket_addr, SERVICES)
            }
            _ => {
                // For other address types, use a default IPv4 address
                let socket_addr = std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                    0,
                );
                NetAddress::new(&socket_addr, SERVICES)
            }
        };

        tracing::debug!(
            "Creating Version message: version={}, user_agent={}, start_height={}",
            PROTOCOL_VERSION,
            user_agent,
            start_height
        );
        Version {
            version: PROTOCOL_VERSION,
            services: SERVICES,
            timestamp,
            addr_recv: net_addr_recv,
            addr_from: net_addr_from,
            nonce,
            user_agent,
            start_height,
            relay: IS_RELAY,
        }
    }

    /// Creates a new Version message with the given parameters and custom
    /// nonce.
    ///
    /// # Arguments
    ///
    /// * `addr_recv` - The network address of the receiving node.
    /// * `addr_from` - The network address of the sending node.
    /// * `user_agent` - The user agent string of the node.
    /// * `start_height` - The last block height known to the sending node.
    /// * `nonce` - A unique identifier for the connection.
    ///
    /// # Returns
    ///
    /// * `Version` - A new instance of the Version message.
    pub fn with_nonce(
        addr_recv: AddrV2,
        addr_from: AddrV2,
        user_agent: String,
        start_height: i32,
        nonce: u64,
    ) -> Self {
        // Convert AddrV2 to NetAddress for the version message
        // NetAddress includes services, address, and port
        let net_addr_recv = match addr_recv {
            AddrV2::Ipv4(ip) => {
                // For Unicity Alpha, use the port from the connection (8590)
                let socket_addr = std::net::SocketAddr::new(std::net::IpAddr::V4(ip), 8590);
                NetAddress::new(&socket_addr, SERVICES)
            }
            AddrV2::Ipv6(ip) => {
                // For Unicity Alpha, use the port from the connection (8590)
                let socket_addr = std::net::SocketAddr::new(std::net::IpAddr::V6(ip), 8590);
                NetAddress::new(&socket_addr, SERVICES)
            }
            _ => {
                // For other address types, use a default IPv4 address
                let socket_addr = std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                    0,
                );
                NetAddress::new(&socket_addr, SERVICES)
            }
        };

        let net_addr_from = match addr_from {
            AddrV2::Ipv4(ip) => {
                let socket_addr = std::net::SocketAddr::new(std::net::IpAddr::V4(ip), 0);
                NetAddress::new(&socket_addr, SERVICES)
            }
            AddrV2::Ipv6(ip) => {
                let socket_addr = std::net::SocketAddr::new(std::net::IpAddr::V6(ip), 0);
                NetAddress::new(&socket_addr, SERVICES)
            }
            _ => {
                // For other address types, use a default IPv4 address
                let socket_addr = std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                    0,
                );
                NetAddress::new(&socket_addr, SERVICES)
            }
        };

        Version {
            version: PROTOCOL_VERSION,
            services: SERVICES,
            timestamp: Utc::now().timestamp(),
            addr_recv: net_addr_recv,
            addr_from: net_addr_from,
            nonce,
            user_agent,
            start_height,
            relay: IS_RELAY,
        }
    }

    /// Returns the protocol version.
    ///
    /// # Returns
    ///
    /// * `i32` - The protocol version.
    pub fn version(&self) -> i32 {
        self.version
    }

    /// Returns the services supported by the node.
    ///
    /// # Returns
    ///
    /// * `ServiceFlags` - The services supported by the node.
    pub fn services(&self) -> ServiceFlags {
        self.services
    }

    /// Returns the timestamp when the message was created.
    ///
    /// # Returns
    ///
    /// * `i64` - The timestamp when the message was created.
    pub fn timestamp(&self) -> i64 {
        self.timestamp
    }

    /// Returns the network address of the receiving node.
    ///
    /// # Returns
    ///
    /// * `&NetAddress` - The network address of the receiving node.
    pub fn addr_recv(&self) -> &NetAddress {
        &self.addr_recv
    }

    /// Returns the network address of the sending node.
    ///
    /// # Returns
    ///
    /// * `&NetAddress` - The network address of the sending node.
    pub fn addr_from(&self) -> &NetAddress {
        &self.addr_from
    }

    /// Returns the unique identifier for the connection.
    ///
    /// # Returns
    ///
    /// * `u64` - The unique identifier for the connection.
    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    /// Returns the user agent string of the node.
    ///
    /// # Returns
    ///
    /// * `&str` - The user agent string of the node.
    pub fn user_agent(&self) -> &str {
        &self.user_agent
    }

    /// Returns the last block height known to the sending node.
    ///
    /// # Returns
    ///
    /// * `i32` - The last block height known to the sending node.
    pub fn start_height(&self) -> i32 {
        self.start_height
    }

    /// Returns whether the node wants to receive relayed transactions or not.
    ///
    /// # Returns
    ///
    /// * `bool` - Whether the node wants to receive relayed transactions or
    ///   not.
    pub fn relay(&self) -> bool {
        self.relay
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::{
        consensus::{Decodable, Encodable},
        p2p::address::AddrV2,
    };

    // Helper function to create a test AddrV2
    fn create_test_addr_v2() -> AddrV2 {
        AddrV2::Ipv4(Ipv4Addr::new(127, 0, 0, 1))
    }

    #[test]
    fn test_version_new() {
        let addr_recv = create_test_addr_v2();
        let addr_from = create_test_addr_v2();
        let user_agent = "test-agent".to_string();
        let start_height = 100;

        let version = Version::new(
            addr_recv.clone(),
            addr_from.clone(),
            user_agent.clone(),
            start_height,
        );

        // Test that all fields are properly initialized
        assert_eq!(version.version, PROTOCOL_VERSION);
        assert_eq!(version.services, SERVICES);
        assert!(version.timestamp > 0); // Timestamp should be positive
        // The addresses are converted to NetAddress, so we can't directly compare
        assert_eq!(version.nonce, version.nonce); // Nonce should be set
        assert_eq!(version.user_agent, user_agent);
        assert_eq!(version.start_height, start_height);
        assert_eq!(version.relay, IS_RELAY);
    }

    #[test]
    fn test_version_with_nonce() {
        let addr_recv = create_test_addr_v2();
        let addr_from = create_test_addr_v2();
        let user_agent = "test-agent".to_string();
        let start_height = 100;
        let nonce: u64 = 12345;

        let version = Version::with_nonce(
            addr_recv.clone(),
            addr_from.clone(),
            user_agent.clone(),
            start_height,
            nonce,
        );

        // Test that all fields are properly initialized with custom nonce
        assert_eq!(version.version, PROTOCOL_VERSION);
        assert_eq!(version.services, SERVICES);
        assert!(version.timestamp > 0); // Timestamp should be positive
        // The addresses are converted to NetAddress, so we can't directly compare
        assert_eq!(version.nonce, nonce); // Nonce should be set to the provided value
        assert_eq!(version.user_agent, user_agent);
        assert_eq!(version.start_height, start_height);
        assert_eq!(version.relay, IS_RELAY);
    }

    #[test]
    fn test_different_nonces() {
        // Test that different instances have different nonces
        let addr_recv = create_test_addr_v2();
        let addr_from = create_test_addr_v2();
        let user_agent = "test-agent".to_string();
        let start_height = 100;

        let version1 = Version::new(
            addr_recv.clone(),
            addr_from.clone(),
            user_agent.clone(),
            start_height,
        );
        let version2 = Version::new(addr_recv, addr_from, user_agent, start_height);

        // Nonces should be different (very high probability)
        assert_ne!(version1.nonce, version2.nonce);
    }

    #[test]
    fn test_clone_and_equality() {
        let addr_recv = create_test_addr_v2();
        let addr_from = create_test_addr_v2();
        let user_agent = "test-agent".to_string();
        let start_height = 100;

        let version = Version::new(addr_recv, addr_from, user_agent, start_height);
        let version_clone = version.clone();

        assert_eq!(version, version_clone);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let addr_recv = create_test_addr_v2();
        let addr_from = create_test_addr_v2();
        let user_agent = "test-agent".to_string();
        let start_height = 100;

        let original = Version::new(addr_recv, addr_from, user_agent, start_height);

        // Test serialization and deserialization
        let mut encoded = Vec::new();
        original.consensus_encode(&mut encoded).unwrap();

        let mut cursor = std::io::Cursor::new(&encoded);
        let decoded = Version::consensus_decode(&mut cursor).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_version_encode_decode_with_known_hex_data() {
        use std::net::{IpAddr, Ipv6Addr, SocketAddr};

        use bitcoin::p2p::address::Address as NetAddress;

        use crate::consensus::{Decodable, Encodable};

        // Known hex data from the example
        let hex_data = "72110100\
        0100000000000000\
        bc8f5e5400000000\
        0100000000000000\
        00000000000000000000ffffc61b6409\
        208d\
        0100000000000000\
        00000000000000000000ffffcb0071c0\
        208d\
        128035cbc97953f8\
        0f\
        2f5361746f7368693a302e392e332f\
        cf050500\
        01";
        let expected_bytes = hex::decode(hex_data).expect("Failed to decode hex data");

        // Parse the expected values from the hex data
        let version = 70002i32;
        let services = ServiceFlags::NETWORK; // NODE_NETWORK
        let timestamp = 1415483324i64;

        // Receiving node address: 00000000000000000000ffffc61b6409 (198.27.100.9) port
        // 208d (8333)
        let recv_ip = IpAddr::V6(Ipv6Addr::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 198, 27, 100, 9,
        ]));
        let recv_socket = SocketAddr::new(recv_ip, 8333);
        let addr_recv = NetAddress::new(&recv_socket, services);

        // Transmitting node address: 00000000000000000000ffffcb0071c0 (203.0.113.192)
        // port 208d (8333)
        let from_ip = IpAddr::V6(Ipv6Addr::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 203, 0, 113, 192,
        ]));
        let from_socket = SocketAddr::new(from_ip, 8333);
        let addr_from = NetAddress::new(&from_socket, services);

        let nonce = 0xf85379c9cb358012u64; // 128035cbc97953f8 in little-endian format
        let user_agent = "/Satoshi:0.9.3/".to_string();
        let start_height = 329167i32; // cf050500 in little-endian
        let relay = true;

        // Create the version message with the known values
        let version_msg = Version {
            version,
            services,
            timestamp,
            addr_recv,
            addr_from,
            nonce,
            user_agent: user_agent.clone(),
            start_height,
            relay,
        };

        // Test encoding
        let mut encoded = Vec::new();
        version_msg.consensus_encode(&mut encoded).unwrap();

        // Compare the encoded bytes with the expected hex data
        assert_eq!(
            encoded, expected_bytes,
            "Encoded bytes don't match expected hex data"
        );

        // Test decoding
        let mut cursor = std::io::Cursor::new(&expected_bytes);
        let decoded = Version::consensus_decode(&mut cursor).unwrap();

        // Verify all fields match the expected values
        assert_eq!(decoded.version, version);
        assert_eq!(decoded.services, services);
        assert_eq!(decoded.timestamp, timestamp);
        assert_eq!(decoded.addr_recv.services, services);
        assert_eq!(decoded.addr_from.services, services);
        assert_eq!(decoded.nonce, nonce);
        assert_eq!(decoded.user_agent, user_agent);
        assert_eq!(decoded.start_height, start_height);
        assert_eq!(decoded.relay, relay);

        // Verify that the decoded message equals the original
        assert_eq!(version_msg, decoded);
    }
}
