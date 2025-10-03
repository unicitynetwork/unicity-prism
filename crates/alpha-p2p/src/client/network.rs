//! Network message handling for Bitcoin P2P protocol.
//!
//! This module provides functionality for wrapping and unwrapping Bitcoin P2P messages
//! in the network protocol format, including magic bytes, command strings, and checksums.

use crate::blockdata::block::Header;
use crate::client::message::{Message, MessageCommand};
use crate::consensus::{Decodable, Encodable};
use crate::hashes::Sha256Hash;
use crate::io::{Error as IoError, Read, Write};
use crate::p2p::Magic;
use bitcoin::hashes::Hash;
use bitcoin::p2p::message::CommandString;
use thiserror::Error;

/// Errors that can occur during network message handling.
#[derive(Debug, Error)]
pub enum NetworkError {
    /// IO error during network operations.
    #[error("IO error: {0}")]
    Io(#[from] IoError),

    /// Invalid magic bytes in message header.
    #[error("Invalid magic bytes: expected {expected:x}, got {actual:x}")]
    InvalidMagic {
        /// The expected magic bytes value
        expected: u32,
        /// The actual magic bytes value received
        actual: u32,
    },

    /// Message payload too large.
    #[error("Message payload too large: {size} bytes (max: {max} bytes)")]
    PayloadTooLarge {
        /// The actual payload size in bytes
        size: u32,
        /// The maximum allowed payload size in bytes
        max: u32,
    },

    /// Invalid checksum in message header.
    #[error("Invalid checksum: expected {expected:x}, got {actual:x}")]
    InvalidChecksum {
        /// The expected checksum value
        expected: u32,
        /// The actual checksum value received
        actual: u32,
    },

    /// Invalid command string in message header.
    #[error("Invalid command string: {0}")]
    InvalidCommand(String),

    /// Consensus encoding/decoding error.
    #[error("Consensus error: {0}")]
    Consensus(#[from] crate::consensus::EncodeDecodeError),
}

/// Bitcoin P2P network message header.
///
/// The header contains metadata about the message including magic bytes,
/// command string, payload length, and checksum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkMessageHeader {
    /// Network magic bytes to identify the cryptocurrency network.
    pub magic: Magic,
    /// Command string (null-padded to 12 bytes).
    pub command: CommandString,
    /// Length of the payload in bytes.
    pub length: u32,
    /// First 4 bytes of SHA256(SHA256(payload)).
    pub checksum: [u8; 4],
}

impl NetworkMessageHeader {
    /// Size of the network message header in bytes.
    pub const SIZE: usize = 24; // 4 (magic) + 12 (command) + 4 (length) + 4 (checksum)

    /// Creates a new network message header.
    pub fn new(
        magic: Magic,
        command: CommandString,
        length: u32,
        payload: &[u8],
    ) -> Result<Self, NetworkError> {
        // Calculate checksum
        let hash: Sha256Hash = Hash::hash(payload);
        let checksum = [
            hash.as_byte_array()[0],
            hash.as_byte_array()[1],
            hash.as_byte_array()[2],
            hash.as_byte_array()[3],
        ];

        Ok(Self {
            magic,
            command,
            length,
            checksum,
        })
    }

    /// Validates the header against expected values.
    pub fn validate(&self, expected_magic: Magic, payload: &[u8]) -> Result<(), NetworkError> {
        // Check magic bytes
        if self.magic != expected_magic {
            return Err(NetworkError::InvalidMagic {
                expected: u32::from_le_bytes(expected_magic.to_bytes()),
                actual: u32::from_le_bytes(self.magic.to_bytes()),
            });
        }

        // Check payload length
        if self.length as usize != payload.len() {
            return Err(NetworkError::PayloadTooLarge {
                size: self.length,
                max: u32::try_from(payload.len()).unwrap_or(u32::MAX),
            });
        }

        // Check checksum
        let hash = Sha256Hash::hash(payload);
        let expected_checksum = [
            hash.as_byte_array()[0],
            hash.as_byte_array()[1],
            hash.as_byte_array()[2],
            hash.as_byte_array()[3],
        ];

        if self.checksum != expected_checksum {
            return Err(NetworkError::InvalidChecksum {
                expected: u32::from_le_bytes(expected_checksum),
                actual: u32::from_le_bytes(self.checksum),
            });
        }

        Ok(())
    }
}

impl Encodable for NetworkMessageHeader {
    fn consensus_encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, IoError> {
        let mut len: usize = 0;

        // Encode magic bytes
        len = len.saturating_add(self.magic.consensus_encode(writer)?);

        // Encode command string (12 bytes, null-padded)
        let command_string = self.command.to_string();
        let command_bytes = command_string.as_bytes();
        let mut padded_command = [0u8; 12];
        let copy_len = std::cmp::min(command_bytes.len(), 12);
        if let Some(dst_slice) = padded_command.get_mut(..copy_len)
            && let Some(src_slice) = command_bytes.get(..copy_len)
        {
            dst_slice.copy_from_slice(src_slice);
        }
        len = len.saturating_add(padded_command.consensus_encode(writer)?);

        // Encode length
        len = len.saturating_add(self.length.consensus_encode(writer)?);

        // Encode checksum
        len = len.saturating_add(self.checksum.consensus_encode(writer)?);

        Ok(len)
    }
}

impl Decodable for NetworkMessageHeader {
    fn consensus_decode<R: Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, crate::consensus::EncodeDecodeError> {
        // Decode magic bytes
        let magic = Magic::consensus_decode(reader)?;

        // Decode command string (12 bytes)
        let mut command_bytes = [0u8; 12];
        reader.read_exact(&mut command_bytes)?;

        // Find null terminator
        let end_pos = command_bytes.iter().position(|&b| b == 0).unwrap_or(12);
        let command_bytes_slice = command_bytes.get(..end_pos).ok_or_else(|| {
            crate::consensus::EncodeDecodeError::ParseFailed("Invalid command string slice")
        })?;
        let command_str = std::str::from_utf8(command_bytes_slice).map_err(|_| {
            crate::consensus::EncodeDecodeError::ParseFailed("Invalid command string")
        })?;

        let command = CommandString::try_from(command_str).map_err(|_| {
            crate::consensus::EncodeDecodeError::ParseFailed("Invalid command string")
        })?;

        // Decode length
        let length = u32::consensus_decode(reader)?;

        // Decode checksum
        let checksum = <[u8; 4]>::consensus_decode(reader)?;

        Ok(Self {
            magic,
            command,
            length,
            checksum,
        })
    }
}

/// A complete Bitcoin P2P network message.
///
/// This wraps a message payload with the network protocol header,
/// providing serialization and deserialization for network transmission.
#[derive(Debug, Clone)]
pub struct NetworkMessage<H: Header> {
    /// Network message header.
    pub header: NetworkMessageHeader,
    /// Message payload.
    pub payload: Message<H>,
}

impl<H> NetworkMessage<H>
where
    H: Header,
{
    /// Maximum payload size for a network message (32 MB).
    pub const MAX_PAYLOAD_SIZE: u32 = 32 * 1024 * 1024;

    /// Creates a new network message from a payload.
    pub fn new(magic: Magic, payload: Message<H>) -> Result<Self, NetworkError> {
        // Determine actual command based on message type first
        let msg_command = payload.command();

        // Serialize payload
        let mut payload_bytes = Vec::new();
        payload.consensus_encode(&mut payload_bytes)?;

        tracing::info!(
            "Serialized {} payload: {} bytes",
            msg_command.as_str(),
            payload_bytes.len()
        );

        // Check payload size
        if payload_bytes.len() > Self::MAX_PAYLOAD_SIZE as usize {
            return Err(NetworkError::PayloadTooLarge {
                size: u32::try_from(payload_bytes.len()).unwrap_or(u32::MAX),
                max: Self::MAX_PAYLOAD_SIZE,
            });
        }

        let command = msg_command.to_command_string()?;

        let header = NetworkMessageHeader::new(
            magic,
            command,
            u32::try_from(payload_bytes.len()).unwrap_or(u32::MAX),
            &payload_bytes,
        )?;

        tracing::info!(
            "Created {} network message: {} bytes",
            msg_command.as_str(),
            header.length
        );

        Ok(Self { header, payload })
    }

    /// Serializes the complete network message to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, NetworkError> {
        let mut bytes = Vec::new();

        // Encode header
        self.header.consensus_encode(&mut bytes)?;

        // Encode payload
        self.payload.consensus_encode(&mut bytes)?;

        Ok(bytes)
    }

    /// Deserializes a network message from bytes.
    pub fn from_bytes(bytes: &[u8], magic: Magic) -> Result<Self, NetworkError> {
        if bytes.len() < NetworkMessageHeader::SIZE {
            return Err(NetworkError::Io(IoError::new(
                bitcoin::io::ErrorKind::UnexpectedEof,
                "Insufficient bytes for message header",
            )));
        }

        let mut cursor = std::io::Cursor::new(bytes);

        // Decode header
        let header = NetworkMessageHeader::consensus_decode(&mut cursor)?;

        // Validate header
        if header.magic != magic {
            return Err(NetworkError::InvalidMagic {
                expected: u32::from_le_bytes(magic.to_bytes()),
                actual: u32::from_le_bytes(header.magic.to_bytes()),
            });
        }

        // Check payload size
        if header.length > Self::MAX_PAYLOAD_SIZE {
            return Err(NetworkError::PayloadTooLarge {
                size: header.length,
                max: Self::MAX_PAYLOAD_SIZE,
            });
        }

        // Extract payload
        let cursor_pos = usize::try_from(cursor.position()).unwrap_or(0);
        if cursor_pos > bytes.len() {
            return Err(NetworkError::Io(IoError::new(
                bitcoin::io::ErrorKind::UnexpectedEof,
                "Cursor position beyond buffer",
            )));
        }

        let remaining_bytes = bytes.len().saturating_sub(cursor_pos);
        if remaining_bytes != header.length as usize {
            return Err(NetworkError::PayloadTooLarge {
                size: header.length,
                max: u32::try_from(remaining_bytes).unwrap_or(u32::MAX),
            });
        }

        let payload_bytes = bytes.get(cursor_pos..).ok_or_else(|| {
            NetworkError::Io(IoError::new(
                bitcoin::io::ErrorKind::UnexpectedEof,
                "Invalid payload slice",
            ))
        })?;

        // Validate checksum
        header.validate(magic, payload_bytes)?;

        // Decode payload based on command
        let mut cursor = std::io::Cursor::new(payload_bytes);
        let payload = MessageCommand::parse_and_decode(&header.command, &mut cursor)?;

        Ok(Self { header, payload })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockdata::block::BitcoinHeader;
    use crate::client::message::connection::{SendCmpct, Version};
    use crate::client::message::{Connection, Message};
    use crate::network::Network;
    use crate::p2p::address::AddrV2;
    use std::net::Ipv4Addr;

    #[test]
    fn test_network_message_header_roundtrip() {
        let magic = Magic::from(Network::Testnet);
        let command = CommandString::try_from("version").unwrap();
        let payload = b"test payload";
        let length = payload.len() as u32;

        let header = NetworkMessageHeader::new(magic, command.clone(), length, payload).unwrap();

        // Test encoding
        let mut encoded = Vec::new();
        header.consensus_encode(&mut encoded).unwrap();

        // Test decoding
        let mut cursor = std::io::Cursor::new(&encoded);
        let decoded = NetworkMessageHeader::consensus_decode(&mut cursor).unwrap();

        assert_eq!(decoded.magic, magic);
        assert_eq!(decoded.command, command);
        assert_eq!(decoded.length, length);
    }

    #[test]
    fn test_network_message_roundtrip() {
        let magic = Magic::from(Network::Testnet);

        // Create a test version message
        let addr_recv = AddrV2::Ipv4(Ipv4Addr::new(127, 0, 0, 1));
        let addr_from = AddrV2::Ipv4(Ipv4Addr::new(127, 0, 0, 1));
        let version = Version::new(addr_recv, addr_from, "test".to_string(), 0);
        let message: Message<BitcoinHeader> = Message::Connection(Connection::Version(version));

        // Create network message
        let network_msg = NetworkMessage::new(magic, message.clone()).unwrap();

        // Test serialization
        let bytes = network_msg.to_bytes().unwrap();

        // Test deserialization
        let decoded: NetworkMessage<BitcoinHeader> =
            NetworkMessage::from_bytes(&bytes, magic).unwrap();

        // Verify the payload is the same
        match (network_msg.payload, decoded.payload) {
            (
                Message::Connection(Connection::Version(orig)),
                Message::Connection(Connection::Version(dec)),
            ) => {
                assert_eq!(orig.version(), dec.version());
                assert_eq!(orig.user_agent(), dec.user_agent());
            }
            _ => panic!("Message types don't match"),
        }
    }

    #[test]
    fn test_invalid_magic() {
        let magic = Magic::from(Network::Testnet);
        let wrong_magic = Magic::from(Network::Mainnet);

        // Create a test message
        let addr_recv = AddrV2::Ipv4(Ipv4Addr::new(127, 0, 0, 1));
        let addr_from = AddrV2::Ipv4(Ipv4Addr::new(127, 0, 0, 1));
        let version = Version::new(addr_recv, addr_from, "test".to_string(), 0);
        let message: Message<BitcoinHeader> = Message::Connection(Connection::Version(version));

        // Create network message with testnet magic
        let network_msg = NetworkMessage::new(magic, message).unwrap();
        let bytes = network_msg.to_bytes().unwrap();

        // Try to decode with mainnet magic (should fail)
        let result = NetworkMessage::<BitcoinHeader>::from_bytes(&bytes, wrong_magic);
        assert!(matches!(result, Err(NetworkError::InvalidMagic { .. })));
    }

    #[test]
    fn test_invalid_checksum() {
        let magic = Magic::from(Network::Testnet);

        // Create a test message
        let addr_recv = AddrV2::Ipv4(Ipv4Addr::new(127, 0, 0, 1));
        let addr_from = AddrV2::Ipv4(Ipv4Addr::new(127, 0, 0, 1));
        let version = Version::new(addr_recv, addr_from, "test".to_string(), 0);
        let message: Message<BitcoinHeader> = Message::Connection(Connection::Version(version));

        // Create network message
        let network_msg = NetworkMessage::new(magic, message).unwrap();
        let mut bytes = network_msg.to_bytes().unwrap();

        // Corrupt the checksum
        bytes[20] ^= 0xFF;

        // Try to decode (should fail)
        let result = NetworkMessage::<BitcoinHeader>::from_bytes(&bytes, magic);
        assert!(matches!(result, Err(NetworkError::InvalidChecksum { .. })));
    }

    #[test]
    fn test_sendcmpct_message_roundtrip() {
        let magic = Magic::from(Network::Testnet);

        // Create a sendcmpct message with announce=true, version=1
        let sendcmpct = SendCmpct::new(true, 1);
        let message: Message<BitcoinHeader> = Message::Connection(Connection::SendCmpct(sendcmpct));

        // Create network message
        let network_msg = NetworkMessage::new(magic, message.clone()).unwrap();

        // Test serialization
        let bytes = network_msg.to_bytes().unwrap();

        // Test deserialization
        let decoded: NetworkMessage<BitcoinHeader> =
            NetworkMessage::from_bytes(&bytes, magic).unwrap();

        // Verify the payload is the same
        match (network_msg.payload, decoded.payload) {
            (
                Message::Connection(Connection::SendCmpct(orig)),
                Message::Connection(Connection::SendCmpct(dec)),
            ) => {
                assert_eq!(orig.announce(), dec.announce());
                assert_eq!(orig.version(), dec.version());
            }
            _ => panic!("Message types don't match"),
        }
    }

    #[test]
    fn test_sendcmpct_message_serialization() {
        let magic = Magic::from(Network::Testnet);

        // Create a sendcmpct message with announce=false, version=1
        let sendcmpct = SendCmpct::new(false, 1);
        let message: Message<BitcoinHeader> = Message::Connection(Connection::SendCmpct(sendcmpct));

        // Create network message
        let network_msg = NetworkMessage::new(magic, message).unwrap();

        // Test serialization
        let bytes = network_msg.to_bytes().unwrap();

        // Verify the command string is "sendcmpct"
        assert_eq!(network_msg.header.command.to_string(), "sendcmpct");

        // Verify the payload size (9 bytes: 1 for announce, 8 for version)
        assert_eq!(network_msg.header.length, 9);

        // Verify the exact serialized bytes
        let expected_bytes = [
            11, 17, 9, 7, 115, 101, 110, 100, 99, 109, 112, 99, 116, 0, 0, 0, 9, 0, 0, 0, 204, 254,
            16, 74, 0, 1, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(bytes, expected_bytes);
    }

    #[test]
    fn test_sendcmpct_message_with_version_2() {
        let magic = Magic::from(Network::Testnet);

        // Create a sendcmpct message with announce=true, version=2
        let sendcmpct = SendCmpct::new(true, 2);
        let message: Message<BitcoinHeader> = Message::Connection(Connection::SendCmpct(sendcmpct));

        // Create network message
        let network_msg = NetworkMessage::new(magic, message.clone()).unwrap();

        // Test serialization
        let bytes = network_msg.to_bytes().unwrap();

        // Test deserialization
        let decoded: NetworkMessage<BitcoinHeader> =
            NetworkMessage::from_bytes(&bytes, magic).unwrap();

        // Verify the payload is the same
        match (network_msg.payload, decoded.payload) {
            (
                Message::Connection(Connection::SendCmpct(orig)),
                Message::Connection(Connection::SendCmpct(dec)),
            ) => {
                assert_eq!(orig.announce(), dec.announce());
                assert_eq!(orig.version(), dec.version());
                assert_eq!(dec.version(), 2);
            }
            _ => panic!("Message types don't match"),
        }
    }
}
