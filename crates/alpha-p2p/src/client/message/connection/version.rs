use bitcoin::p2p::address::AddrV2;
use bitcoin::p2p::ServiceFlags;
use chrono::Utc;

const IS_RELAY: bool = false;
const PROTOCOL_VERSION: i32 = 70016;
const SERVICES: ServiceFlags = ServiceFlags::NONE;

/// Represents a version message in the P2P protocol.
///
/// A version message is used to initiate a connection between two peers.
/// It contains information about the protocol version, services supported,
/// timestamps, network addresses, user agent, and other relevant details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    /// The version of the protocol being used.
    pub version: i32,
    /// The services supported by the node.
    pub services: ServiceFlags,
    /// The timestamp when the message was created.
    pub timestamp: i64,
    /// The network address of the receiving node.
    pub addr_recv: AddrV2,
    /// The network address of the sending node.
    pub addr_from: AddrV2,
    /// A unique identifier for the connection, typically a random nonce.
    pub nonce: u64,
    /// The user agent string of the node, typically identifying the software and version.
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
        let nonce = rand::random::<u64>();
        Version {
            version: PROTOCOL_VERSION,
            services: SERVICES,
            timestamp: Utc::now().timestamp(),
            addr_recv,
            addr_from,
            nonce,
            user_agent,
            start_height,
            relay: IS_RELAY,
        }
    }
}
