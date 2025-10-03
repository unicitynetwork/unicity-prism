//! SendCmpct message implementation for BIP 152 (Compact Blocks).
//!
//! The "sendcmpct" message is defined as a message containing a 1-byte integer
//! followed by a 8-byte integer. The first integer is interpreted as a boolean
//! and should have a value of either 1 or 0. The second integer is be
//! interpreted as a little-endian version number.

use alpha_p2p_derive::ConsensusCodec;

/// Represents a sendcmpct message in the P2P protocol (BIP 152).
///
/// This message is used to signal to a peer whether they should announce new
/// blocks using compact blocks (cmpctblock messages) or traditional inv/headers
/// messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ConsensusCodec)]
pub struct SendCmpct {
    /// A boolean indicating whether to announce new blocks using cmpctblock
    /// messages. true (1) = announce new blocks by sending cmpctblock
    /// messages false (0) = announce new blocks by sending invs or headers
    pub announce: bool,

    /// A little-endian version number for compact blocks.
    /// Version 2 compact blocks should be specified by setting version to 2.
    /// Nodes should treat the peer as if they had not received the message if
    /// the version is something other than 1.
    pub version: u64,
}

impl SendCmpct {
    /// Creates a new SendCmpct message with the given parameters.
    ///
    /// # Arguments
    ///
    /// * `announce` - Whether to announce new blocks using cmpctblock messages
    /// * `version` - The compact blocks protocol version
    ///
    /// # Returns
    ///
    /// * `SendCmpct` - A new instance of the SendCmpct message
    pub fn new(announce: bool, version: u64) -> Self {
        Self { announce, version }
    }

    /// Creates a SendCmpct message that enables compact block announcements.
    ///
    /// # Arguments
    ///
    /// * `version` - The compact blocks protocol version (typically 1 or 2)
    ///
    /// # Returns
    ///
    /// * `SendCmpct` - A SendCmpct message with announce=true
    pub fn enable(version: u64) -> Self {
        Self {
            announce: true,
            version,
        }
    }

    /// Creates a SendCmpct message that disables compact block announcements.
    ///
    /// # Returns
    ///
    /// * `SendCmpct` - A SendCmpct message with announce=false
    pub fn disable() -> Self {
        Self {
            announce: false,
            version: 0,
        }
    }

    /// Returns whether to announce new blocks using cmpctblock messages.
    ///
    /// # Returns
    ///
    /// * `bool` - true if compact blocks should be used, false otherwise
    pub fn announce(&self) -> bool {
        self.announce
    }

    /// Returns the compact blocks protocol version.
    ///
    /// # Returns
    ///
    /// * `u64` - The version number
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Checks if this is a valid sendcmpct message according to BIP 152.
    ///
    /// According to BIP 152, nodes should treat the peer as if they had not
    /// received the message if the version is something other than 1.
    ///
    /// # Returns
    ///
    /// * `bool` - true if the message is valid, false otherwise
    pub fn is_valid(&self) -> bool {
        self.version == 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{Decodable, Encodable};

    #[test]
    fn test_sendcmpct_new() {
        let sendcmpct = SendCmpct::new(true, 1);
        assert!(sendcmpct.announce);
        assert_eq!(sendcmpct.version, 1);
    }

    #[test]
    fn test_sendcmpct_enable() {
        let sendcmpct = SendCmpct::enable(2);
        assert!(sendcmpct.announce);
        assert_eq!(sendcmpct.version, 2);
    }

    #[test]
    fn test_sendcmpct_disable() {
        let sendcmpct = SendCmpct::disable();
        assert!(!sendcmpct.announce);
        assert_eq!(sendcmpct.version, 0);
    }

    #[test]
    fn test_sendcmpct_accessors() {
        let sendcmpct = SendCmpct::new(true, 1);
        assert!(sendcmpct.announce());
        assert_eq!(sendcmpct.version(), 1);
    }

    #[test]
    fn test_sendcmpct_is_valid() {
        let valid = SendCmpct::new(true, 1);
        let invalid = SendCmpct::new(true, 2);

        assert!(valid.is_valid());
        assert!(!invalid.is_valid());
    }

    #[test]
    fn test_sendcmpct_serialization_roundtrip() {
        let original = SendCmpct::new(true, 1);

        // Test serialization
        let mut encoded = Vec::new();
        original.consensus_encode(&mut encoded).unwrap();

        // Test deserialization
        let mut cursor = std::io::Cursor::new(&encoded);
        let decoded = SendCmpct::consensus_decode(&mut cursor).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_sendcmpct_serialization_with_known_values() {
        // Test with announce=true, version=1
        let sendcmpct = SendCmpct::new(true, 1);

        let mut encoded = Vec::new();
        sendcmpct.consensus_encode(&mut encoded).unwrap();

        // Should be 9 bytes: 1 byte for announce (boolean as u8), 8 bytes for version
        // (u64)
        assert_eq!(encoded.len(), 9);

        // First byte should be 1 (true)
        assert_eq!(encoded[0], 1);

        // Next 8 bytes should be version 1 in little-endian
        assert_eq!(encoded[1], 1);
        for byte in encoded.iter().take(9).skip(2) {
            assert_eq!(*byte, 0);
        }
    }

    #[test]
    fn test_sendcmpct_clone_and_equality() {
        let sendcmpct = SendCmpct::new(false, 1);
        let clone = sendcmpct;

        assert_eq!(sendcmpct, clone);
    }
}
