//! Bitcoin P2P Network Message Types
//!
//! This module defines the complete set of message types used in Bitcoin's P2P
//! network protocol. Messages are categorized into three main groups:
//!
//! 1. **Connection messages** - Handshake and keep-alive communication
//! 2. **Request messages** - Outgoing requests from this client to peers
//! 3. **Response messages** - Incoming responses to requests from peers
//!
//! The enum structure provides type safety and clear categorization of all P2P
//! network messages, making it easy to handle different message types
//! appropriately in the Bitcoin client.

// See: https://developer.bitcoin.org/reference/p2p_networking.html#data-messages
// Only requests are implemented as this client is not meant to relay.

pub(crate) mod connection;
pub mod get_data;
pub mod inventory;
pub(crate) mod request;
pub(crate) mod response;

use std::io;

use bitcoin::{consensus::Encodable, p2p::message::CommandString};
pub use connection::{Ping, Pong, SendCmpct, Version};
pub use request::GetHeaders;

pub(crate) use crate::alpha::client::message::response::{Headers, NotFound, Tx};
use crate::alpha::{
    blockdata::block::{Block, Header},
    client::{
        message::{connection::FeeFilter, get_data::GetData},
        network::NetworkError,
    },
    consensus::Decodable,
    io::{Error, Write},
};

/// Enum for message commands to avoid string matching
#[derive(Debug, Clone, PartialEq)]
pub enum MessageCommand {
    /// Version message - initial handshake message
    Version,
    /// Version acknowledgment - confirms handshake completion
    VerAck,
    /// Ping message - keep-alive message
    Ping,
    /// Pong message - response to ping
    Pong,
    /// WtxIdRelay message - signal preference for wtxid-based transaction relay
    WtxIdRelay,
    /// GetHeaders message - request for block headers
    GetHeaders,
    /// GetData message - request for specific data items
    GetData,
    /// Headers message - response with block headers
    Headers,
    /// Block message - full block data
    Block,
    /// Tx message - full transaction data
    Tx,
    /// NotFound message - requested data not found
    NotFound,
    /// SendAddrV2 message - signal preference for addrv2 format
    SendAddrV2,
    /// SendCmpct message - signal preference for compact block announcements
    SendCmpct,
    /// FeeFilter message - set minimum fee rate for transaction relay
    FeeFilter,
    /// Unknown command that wraps the command string
    Unknown(String),
}

impl MessageCommand {
    /// Parse a command string and decode the corresponding message payload
    ///
    /// This function combines the functionality of parsing a command string and
    /// decoding the message payload into a single operation.
    pub fn parse_and_decode<H: Header>(
        command: &CommandString,
        cursor: &mut io::Cursor<&[u8]>,
    ) -> Result<Message<H>, NetworkError> {
        match command.to_string().as_str() {
            "version" => {
                let version = Version::consensus_decode(cursor).map_err(NetworkError::Consensus)?;
                Ok(Message::Connection(Connection::Version(version)))
            }
            "verack" => Ok(Message::Connection(Connection::VerAck)),
            "ping" => {
                let ping = Ping::consensus_decode(cursor).map_err(NetworkError::Consensus)?;
                Ok(Message::Connection(Connection::Ping(ping)))
            }
            "pong" => {
                let pong = Pong::consensus_decode(cursor).map_err(NetworkError::Consensus)?;
                Ok(Message::Connection(Connection::Pong(pong)))
            }
            "wtxidrelay" => Ok(Message::Connection(Connection::WtxIdRelay)),
            "getheaders" => {
                let get_headers =
                    GetHeaders::consensus_decode(cursor).map_err(NetworkError::Consensus)?;
                Ok(Message::Request(Request::GetHeaders(get_headers)))
            }
            "getdata" => {
                let get_data =
                    GetData::consensus_decode(cursor).map_err(NetworkError::Consensus)?;
                Ok(Message::Request(Request::GetData(get_data)))
            }
            "headers" => {
                let headers = Headers::consensus_decode(cursor).map_err(NetworkError::Consensus)?;
                Ok(Message::Response(Response::Headers(headers)))
            }
            "block" => {
                let block = response::StandardBlock::consensus_decode(cursor)
                    .map_err(NetworkError::Consensus)?;
                Ok(Message::Response(Response::Block(Block {
                    header: block.header,
                    transactions: block.transactions,
                    witness_root: None,
                })))
            }
            "tx" => {
                let tx = Tx::consensus_decode(cursor).map_err(NetworkError::Consensus)?;
                Ok(Message::Response(Response::Tx(tx)))
            }
            "notfound" => {
                let not_found =
                    NotFound::consensus_decode(cursor).map_err(NetworkError::Consensus)?;
                Ok(Message::Response(Response::NotFound(not_found)))
            }
            "sendaddrv2" => Ok(Message::Connection(Connection::SendAddrV2)),
            "sendcmpct" => {
                let sendcmpct =
                    SendCmpct::consensus_decode(cursor).map_err(NetworkError::Consensus)?;
                Ok(Message::Connection(Connection::SendCmpct(sendcmpct)))
            }
            "feefilter" => {
                let feefilter =
                    FeeFilter::consensus_decode(cursor).map_err(NetworkError::Consensus)?;
                Ok(Message::Connection(Connection::FeeFilter(feefilter)))
            }
            _ => Err(NetworkError::InvalidCommand(format!(
                "Unknown command: {}",
                command
            ))),
        }
    }

    /// Convert from a CommandString
    pub fn from_command_string(command: &CommandString) -> Result<Self, NetworkError> {
        match command.to_string().as_str() {
            "version" => Ok(MessageCommand::Version),
            "verack" => Ok(MessageCommand::VerAck),
            "ping" => Ok(MessageCommand::Ping),
            "pong" => Ok(MessageCommand::Pong),
            "wtxidrelay" => Ok(MessageCommand::WtxIdRelay),
            "getheaders" => Ok(MessageCommand::GetHeaders),
            "getdata" => Ok(MessageCommand::GetData),
            "headers" => Ok(MessageCommand::Headers),
            "block" => Ok(MessageCommand::Block),
            "tx" => Ok(MessageCommand::Tx),
            "notfound" => Ok(MessageCommand::NotFound),
            "sendaddrv2" => Ok(MessageCommand::SendAddrV2),
            "sendcmpct" => Ok(MessageCommand::SendCmpct),
            "feefilter" => Ok(MessageCommand::FeeFilter),
            _ => Err(NetworkError::InvalidCommand(format!(
                "Unknown command: {}",
                command
            ))),
        }
    }

    /// Convert to a CommandString
    pub fn to_command_string(&self) -> Result<CommandString, NetworkError> {
        let command_str = self.as_str();
        CommandString::try_from(command_str)
            .map_err(|_| NetworkError::InvalidCommand(command_str.to_string()))
    }

    /// Get the command as a string for logging purposes
    pub fn as_str(&self) -> &str {
        match self {
            MessageCommand::Version => "version",
            MessageCommand::VerAck => "verack",
            MessageCommand::Ping => "ping",
            MessageCommand::Pong => "pong",
            MessageCommand::WtxIdRelay => "wtxidrelay",
            MessageCommand::GetHeaders => "getheaders",
            MessageCommand::GetData => "getdata",
            MessageCommand::Headers => "headers",
            MessageCommand::Block => "block",
            MessageCommand::Tx => "tx",
            MessageCommand::NotFound => "notfound",
            MessageCommand::SendAddrV2 => "sendaddrv2",
            MessageCommand::SendCmpct => "sendcmpct",
            MessageCommand::FeeFilter => "feefilter",
            MessageCommand::Unknown(s) => s,
        }
    }

    /// Deserialize a message payload based on the command type
    pub fn decode_payload<H: Header>(
        &self,
        cursor: &mut io::Cursor<&[u8]>,
    ) -> Result<Message<H>, NetworkError> {
        match self {
            MessageCommand::Version => {
                let version = Version::consensus_decode(cursor).map_err(NetworkError::Consensus)?;
                Ok(Message::Connection(Connection::Version(version)))
            }
            MessageCommand::VerAck => Ok(Message::Connection(Connection::VerAck)),
            MessageCommand::Ping => {
                let ping = Ping::consensus_decode(cursor).map_err(NetworkError::Consensus)?;
                Ok(Message::Connection(Connection::Ping(ping)))
            }
            MessageCommand::Pong => {
                let pong = Pong::consensus_decode(cursor).map_err(NetworkError::Consensus)?;
                Ok(Message::Connection(Connection::Pong(pong)))
            }
            MessageCommand::WtxIdRelay => Ok(Message::Connection(Connection::WtxIdRelay)),
            MessageCommand::GetHeaders => {
                let get_headers =
                    GetHeaders::consensus_decode(cursor).map_err(NetworkError::Consensus)?;
                Ok(Message::Request(Request::GetHeaders(get_headers)))
            }
            MessageCommand::Headers => {
                let headers = Headers::consensus_decode(cursor).map_err(NetworkError::Consensus)?;
                Ok(Message::Response(Response::Headers(headers)))
            }
            MessageCommand::Block => {
                let block = response::StandardBlock::consensus_decode(cursor)
                    .map_err(NetworkError::Consensus)?;
                Ok(Message::Response(Response::Block(Block {
                    header: block.header,
                    transactions: block.transactions,
                    witness_root: None,
                })))
            }
            MessageCommand::Tx => {
                let tx = Tx::consensus_decode(cursor).map_err(NetworkError::Consensus)?;
                Ok(Message::Response(Response::Tx(tx)))
            }
            MessageCommand::NotFound => {
                let not_found =
                    NotFound::consensus_decode(cursor).map_err(NetworkError::Consensus)?;
                Ok(Message::Response(Response::NotFound(not_found)))
            }
            MessageCommand::SendAddrV2 => Ok(Message::Connection(Connection::SendAddrV2)),
            MessageCommand::SendCmpct => {
                let sendcmpct =
                    SendCmpct::consensus_decode(cursor).map_err(NetworkError::Consensus)?;
                Ok(Message::Connection(Connection::SendCmpct(sendcmpct)))
            }
            MessageCommand::FeeFilter => {
                let feefilter =
                    FeeFilter::consensus_decode(cursor).map_err(NetworkError::Consensus)?;
                Ok(Message::Connection(Connection::FeeFilter(feefilter)))
            }
            MessageCommand::GetData => {
                let get_data =
                    GetData::consensus_decode(cursor).map_err(NetworkError::Consensus)?;
                Ok(Message::Request(Request::GetData(get_data)))
            }
            MessageCommand::Unknown(command) => Err(NetworkError::InvalidCommand(format!(
                "Cannot decode unknown command: {}",
                command
            ))),
        }
    }
}

/// Top-level Bitcoin P2P network message enum.
///
/// This enum represents all possible types of messages that can be sent or
/// received in the Bitcoin P2P network. Each variant contains a specific type
/// of message, allowing for proper handling and dispatching of messages
/// throughout the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message<H: Header> {
    /// Protocol-level messages used for establishing and maintaining
    /// connections.
    ///
    /// These include handshake messages, acknowledgments, and keep-alive
    /// communications that are essential for peer discovery and connection
    /// management.
    Connection(Connection),

    /// Peer-to-peer request messages sent from this client to other peers.
    ///
    /// These are outgoing requests that ask for specific data such as headers,
    /// blocks, or transactions from other nodes in the network.
    Request(Request),

    /// Responses to peer-to-peer request messages received from other peers.
    ///
    /// These are incoming responses that contain the requested data or error
    /// information from other nodes in response to requests made by this
    /// client.
    Response(Response<H>),
}

impl<H: Header> Message<H> {
    /// Get the MessageCommand for this Message
    pub fn command(&self) -> MessageCommand {
        match self {
            Message::Connection(conn) => match conn {
                Connection::Version(_) => MessageCommand::Version,
                Connection::VerAck => MessageCommand::VerAck,
                Connection::Ping(_) => MessageCommand::Ping,
                Connection::Pong(_) => MessageCommand::Pong,
                Connection::WtxIdRelay => MessageCommand::WtxIdRelay,
                Connection::SendAddrV2 => MessageCommand::SendAddrV2,
                Connection::SendCmpct(_) => MessageCommand::SendCmpct,
                Connection::FeeFilter(_) => MessageCommand::FeeFilter,
            },
            Message::Request(req) => match req {
                Request::GetHeaders(_) => MessageCommand::GetHeaders,
                Request::GetData(_) => MessageCommand::GetData,
            },
            Message::Response(resp) => match resp {
                Response::Headers(_) => MessageCommand::Headers,
                Response::Block(_) => MessageCommand::Block,
                Response::Tx(_) => MessageCommand::Tx,
                Response::NotFound(_) => MessageCommand::NotFound,
            },
        }
    }
}

impl<H: Header> Encodable for Message<H> {
    fn consensus_encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, Error> {
        match self {
            Message::Connection(msg) => msg.consensus_encode(writer),
            Message::Request(msg) => msg.consensus_encode(writer),
            Message::Response(msg) => msg.consensus_encode(writer),
        }
    }
}

///
/// These messages are part of the Bitcoin P2P protocol handshake and connection
/// management, including version negotiation, acknowledgments, and keep-alive
/// communication.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// that the handshake has been successfully completed and both peers are
    /// ready.
    VerAck,

    /// Keep-alive message - sent periodically to maintain connection.
    ///
    /// Ping messages are used to test if the peer is still alive and
    /// responsive, and to prevent connection timeouts in idle networks.
    Ping(Ping),

    /// Response to a ping message - sent when receiving a ping from another
    /// peer.
    ///
    /// This is the standard response to keep-alive messages, confirming that
    /// this node is still active and responsive.
    Pong(Pong),

    /// Signal preference for wtxid-based transaction relay (BIP 339).
    ///
    /// This message signals that the node prefers to use transaction
    /// identifiers (wtxids) instead of transaction hashes for transaction
    /// relay. The message has no payload.
    WtxIdRelay,

    /// Signal preference for addrv2 format (BIP 155).
    ///
    /// This message signals that the node wants to receive address messages in
    /// the addrv2 format, which supports more address types than the
    /// original addr format. The message has no payload.
    SendAddrV2,

    /// Signal preference for compact block announcements (BIP 152).
    ///
    /// This message is used to signal to a peer whether they should announce
    /// new blocks using compact blocks (cmpctblock messages) or traditional
    /// inv/headers messages.
    SendCmpct(SendCmpct),

    /// Set minimum fee rate for transaction relay (BIP 133).
    ///
    /// This message informs peers about the minimum fee rate (in satoshis per
    /// kilobyte) for which transactions should be relayed to this peer.
    /// Transactions with fee rates below this value should not be relayed
    /// to this peer.
    FeeFilter(FeeFilter),
}

impl Encodable for Connection {
    fn consensus_encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, Error> {
        match self {
            Connection::Version(msg) => msg.consensus_encode(writer),
            Connection::VerAck => Ok(0), // VerAck has no payload
            Connection::Ping(msg) => msg.consensus_encode(writer),
            Connection::Pong(msg) => msg.consensus_encode(writer),
            Connection::WtxIdRelay => Ok(0), // WtxIdRelay has no payload
            Connection::SendAddrV2 => Ok(0), // SendAddrV2 has no payload
            Connection::SendCmpct(msg) => msg.consensus_encode(writer),
            Connection::FeeFilter(msg) => msg.consensus_encode(writer),
        }
    }
}

/// Request messages sent from this client to other peers in the network.
///
/// These are outgoing requests that ask for specific data from other nodes,
/// such as headers, blocks, or transactions. The client only sends requests
/// and does not relay data to other peers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Request for blocks or transactions.
    ///
    /// The GetHeaders message is used to request headers of blocks starting
    /// from a set of known block hashes, allowing the client to synchronize
    /// its view of the blockchain with other peers.
    GetHeaders(GetHeaders),

    /// Request for specific data items.
    ///
    /// The GetData message is used to request specific blocks, transactions, or
    /// other data items from peers, identified by their inventory vectors.
    GetData(GetData),
}

impl Encodable for Request {
    fn consensus_encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, Error> {
        match self {
            Request::GetHeaders(msg) => msg.consensus_encode(writer),
            Request::GetData(msg) => msg.consensus_encode(writer),
        }
    }
}

/// Response messages received from other peers in the network.
///
/// These are incoming responses to requests made by this client, containing
/// the requested data or error information from other nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response<H: Header> {
    /// Advertise new blocks or transactions.
    ///
    /// This response contains headers of blocks that are available for
    /// synchronization, allowing the requesting node to update its view of
    /// the blockchain.
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
    /// This response indicates that the requested data (block, transaction,
    /// etc.) was not found on this peer. This may occur when the requested
    /// data is unknown to the node or has already been pruned from the
    /// local storage.
    NotFound(NotFound),
}

impl<H: Header> Encodable for Response<H> {
    fn consensus_encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, Error> {
        match self {
            Response::Headers(msg) => msg.consensus_encode(writer),
            Response::Block(msg) => msg.consensus_encode(writer),
            Response::Tx(msg) => msg.consensus_encode(writer),
            Response::NotFound(msg) => msg.consensus_encode(writer),
        }
    }
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

impl From<SendCmpct> for Connection {
    fn from(msg: SendCmpct) -> Self {
        Connection::SendCmpct(msg)
    }
}

impl From<FeeFilter> for Connection {
    fn from(msg: FeeFilter) -> Self {
        Connection::FeeFilter(msg)
    }
}

impl From<GetHeaders> for Request {
    fn from(msg: GetHeaders) -> Self {
        Request::GetHeaders(msg)
    }
}

impl From<GetData> for Request {
    fn from(msg: GetData) -> Self {
        Request::GetData(msg)
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
