//! Bitcoin P2P Network Message Types
//!
//! This module defines the complete set of message types used in Bitcoin's P2P network protocol.
//! Messages are categorized into three main groups:
//!
//! 1. **Connection messages** - Handshake and keep-alive communication
//! 2. **Request messages** - Outgoing requests from this client to peers
//! 3. **Response messages** - Incoming responses to requests from peers
//!
//! The enum structure provides type safety and clear categorization of all P2P network messages,
//! making it easy to handle different message types appropriately in the Bitcoin client.

// See: https://developer.bitcoin.org/reference/p2p_networking.html#data-messages
// Only requests are implemented as this client is not meant to relay.

mod connection;
pub mod get_data;
pub mod inventory;
mod request;
mod response;

use crate::blockdata::block::{Block, Header};
use crate::client::message::response::{Headers, NotFound, Tx};
use alpha_p2p_derive::ConsensusCodec;
pub use connection::{Ping, Pong, VerAck, Version};
pub use request::GetHeaders;

/// Top-level Bitcoin P2P network message enum.
///
/// This enum represents all possible types of messages that can be sent or received
/// in the Bitcoin P2P network. Each variant contains a specific type of message,
/// allowing for proper handling and dispatching of messages throughout the network.
#[derive(Debug, Clone, PartialEq, Eq, ConsensusCodec)]
pub enum Message<H: Header> {
    /// Protocol-level messages used for establishing and maintaining connections.
    ///
    /// These include handshake messages, acknowledgments, and keep-alive communications
    /// that are essential for peer discovery and connection management.
    Connection(Connection),

    /// Peer-to-peer request messages sent from this client to other peers.
    ///
    /// These are outgoing requests that ask for specific data such as headers,
    /// blocks, or transactions from other nodes in the network.
    Request(Request),

    /// Responses to peer-to-peer request messages received from other peers.
    ///
    /// These are incoming responses that contain the requested data or error
    /// information from other nodes in response to requests made by this client.
    Response(Response<H>),
}

/// Connection-level messages used for establishing and maintaining peer connections.
///
/// These messages are part of the Bitcoin P2P protocol handshake and connection management,
/// including version negotiation, acknowledgments, and keep-alive communication.
#[derive(Debug, Clone, PartialEq, Eq, ConsensusCodec)]
pub enum Connection {
    /// Initial handshake message - sent to introduce this node to a peer.
    ///
    /// The version message contains information about the local node such as:
    /// - Protocol version
    /// - Services offered by this node
    /// - Timestamp of when the connection was established
    /// - Address information of both nodes
    Version(Version),

    /// Acknowledgment of handshake completion.
    ///
    /// This message is sent after receiving a version message to confirm
    /// that the handshake has been successfully completed and both peers are ready.
    VerAck(VerAck),

    /// Keep-alive message - sent periodically to maintain connection.
    ///
    /// Ping messages are used to test if the peer is still alive and responsive,
    /// and to prevent connection timeouts in idle networks.
    Ping(Ping),

    /// Response to a ping message - sent when receiving a ping from another peer.
    ///
    /// This is the standard response to keep-alive messages, confirming that
    /// this node is still active and responsive.
    Pong(Pong),
}

/// Request messages sent from this client to other peers in the network.
///
/// These are outgoing requests that ask for specific data from other nodes,
/// such as headers, blocks, or transactions. The client only sends requests
/// and does not relay data to other peers.
#[derive(Debug, Clone, PartialEq, Eq, ConsensusCodec)]
pub enum Request {
    /// Request for blocks or transactions.
    ///
    /// The GetHeaders message is used to request headers of blocks starting from
    /// a set of known block hashes, allowing the client to synchronize its view
    /// of the blockchain with other peers.
    GetHeaders(GetHeaders),
}

/// Response messages received from other peers in the network.
///
/// These are incoming responses to requests made by this client, containing
/// the requested data or error information from other nodes.
#[derive(Debug, Clone, PartialEq, Eq, ConsensusCodec)]
pub enum Response<H: Header> {
    /// Advertise new blocks or transactions.
    ///
    /// This response contains headers of blocks that are available for synchronization,
    /// allowing the requesting node to update its view of the blockchain.
    Headers(Headers<H>),

    /// Full block data.
    ///
    /// This response contains complete, serialized block data that includes
    /// the full block header and all transactions in the block.
    Block(Block<H>),

    /// Full transaction data.
    ///
    /// This response contains complete, serialized transaction data that can be
    /// used to reconstruct the full transaction information.
    Tx(Tx),

    /// Requested data not found.
    ///
    /// This response indicates that the requested data (block, transaction, etc.)
    /// was not found on this peer. This may occur when the requested data is
    /// unknown to the node or has already been pruned from the local storage.
    NotFound(NotFound),
}

// From trait implementations for convenient conversions

impl<H: Header> From<Connection> for Message<H> {
    fn from(msg: Connection) -> Self {
        Message::Connection(msg)
    }
}

impl<H: Header> From<Request> for Message<H> {
    fn from(msg: Request) -> Self {
        Message::Request(msg)
    }
}

impl<H: Header> From<Response<H>> for Message<H> {
    fn from(msg: Response<H>) -> Self {
        Message::Response(msg)
    }
}

impl From<Version> for Connection {
    fn from(msg: Version) -> Self {
        Connection::Version(msg)
    }
}

impl From<VerAck> for Connection {
    fn from(msg: VerAck) -> Self {
        Connection::VerAck(msg)
    }
}

impl From<Ping> for Connection {
    fn from(msg: Ping) -> Self {
        Connection::Ping(msg)
    }
}

impl From<Pong> for Connection {
    fn from(msg: Pong) -> Self {
        Connection::Pong(msg)
    }
}

impl From<GetHeaders> for Request {
    fn from(msg: GetHeaders) -> Self {
        Request::GetHeaders(msg)
    }
}

impl<H: Header> From<Headers<H>> for Response<H> {
    fn from(msg: Headers<H>) -> Self {
        Response::Headers(msg)
    }
}

impl<H: Header> From<Block<H>> for Response<H> {
    fn from(msg: Block<H>) -> Self {
        Response::Block(msg)
    }
}

impl<H: Header> From<Tx> for Response<H> {
    fn from(msg: Tx) -> Self {
        Response::Tx(msg)
    }
}

impl<H: Header> From<NotFound> for Response<H> {
    fn from(msg: NotFound) -> Self {
        Response::NotFound(msg)
    }
}
