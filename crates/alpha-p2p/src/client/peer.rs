use std::net;
use tracing_subscriber::fmt::time::ChronoLocal;

/// The connection kind of the peer.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Kind {
    /// An inbound connection initiated by the remote peer.
    Inbound,
    /// An outbound connection initiated by us.
    Outbound,
}

/// A peer connected to the client.
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
