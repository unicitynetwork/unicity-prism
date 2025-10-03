//! Peer management for the Alpha P2P network.
//!
//! This module defines the Peer struct and related types used to represent
//! and manage connections to other nodes in the Alpha network.

use std::net;

use tracing_subscriber::fmt::time::ChronoLocal;

/// The connection kind of the peer.
///
/// This enum represents whether a connection was initiated by the remote peer
/// (inbound) or by the local node (outbound).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// An inbound connection initiated by the remote peer.
    Inbound,
    /// An outbound connection initiated by us.
    Outbound,
}

/// A peer connected to the client.
///
/// This struct represents a peer node in the Alpha P2P network, containing
/// information about the connection, the peer's capabilities, and its state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    /// The socket address of the peer.
    pub addr: net::SocketAddr,
    /// The local socket address used to connect to the peer.
    pub local_addr: net::SocketAddr,
    /// The connection kind of the peer, either inbound or outbound.
    pub kind: Kind,
    /// When the peer was connected since last time.
    pub connected_since: ChronoLocal,
    /// The peer's best height.
    pub best_height: u64,
    /// The peer's user agent.
    pub user_agent: String,
    /// Whether this peer relays transactions, or not.
    pub relay: bool,
}
