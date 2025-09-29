// See: https://developer.bitcoin.org/reference/p2p_networking.html#data-messages
// Only requests are implement as this client is not meant to relay.

mod connection;
pub mod get_data;
pub mod inventory;
mod request;

pub use connection::{Ping, Pong, VerAck, Version};
pub use request::GetHeaders;

/// Top-level message enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// Protocol-level messages.
    Connection(Connection),
    /// Peer-to-peer messages.
    Request(Request),
    /// Responses to peer-to-peer messages.
    Response(Response),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Connection {
    /// Initial handshake messages.
    Version(Version),
    /// Acknowledgment of handshake.
    VerAck(VerAck),
    /// Keep-alive messages.
    Ping(Ping),
    /// Response to Ping.
    Pong(Pong),
    /// Advertise new blocks or transactions.
    SendHeaders,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Request {
    /// Request for blocks or transactions.
    GetHeaders(GetHeaders),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Response {
    /// Advertise new blocks or transactions.
    Headers,
    /// Full block data.
    Block,
    /// Full transaction data.
    Tx,
    /// Requested data not found.
    NotFound,
}
