//! FeeFilter message implementation for BIP 133 (Fee Filtering).
//!
//! The "feefilter" message is defined as a message containing an 8-byte integer
//! (little-endian) that represents the minimum fee rate (in satoshis per
//! kilobyte) for which transactions should be relayed to this peer.
//!
//! This message was introduced in Bitcoin Core 0.13.0 following the
//! introduction of mempool limiting in Bitcoin Core 0.12.0. It allows a node to
//! inform its peers that it will not accept transactions below a specified fee
//! rate into its mempool, and therefore that the peers can skip relaying inv
//! messages for transactions below that fee rate to that node.

use alpha_p2p_derive::ConsensusCodec;

/// Represents a feefilter message in the P2P protocol (BIP 133).
///
/// This message is used to inform peers about the minimum fee rate for
/// transaction relay. Transactions with fee rates below this value should not
/// be relayed to this peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ConsensusCodec)]
pub struct FeeFilter {
    /// The minimum fee rate (in satoshis per kilobyte) below which
    /// transactions should not be relayed to this peer.
    pub feerate: u64,
}

impl FeeFilter {
    /// Creates a new FeeFilter message with the given fee rate.
    ///
    /// # Arguments
    ///
    /// * `feerate` - The minimum fee rate in satoshis per kilobyte
    ///
    /// # Returns
    ///
    /// * `FeeFilter` - A new instance of the FeeFilter message
    pub fn new(feerate: u64) -> Self {
        Self { feerate }
    }

    /// Returns the minimum fee rate.
    ///
    /// # Returns
    ///
    /// * `u64` - The minimum fee rate in satoshis per kilobyte
    pub fn feerate(&self) -> u64 {
        self.feerate
    }

    /// Sets the minimum fee rate.
    ///
    /// # Arguments
    ///
    /// * `feerate` - The new minimum fee rate in satoshis per kilobyte
    pub fn set_feerate(&mut self, feerate: u64) {
        self.feerate = feerate;
    }

    /// Creates a FeeFilter message from satoshis per kilobyte.
    ///
    /// This is a convenience method that makes it clear the unit being used.
    ///
    /// # Arguments
    ///
    /// * `sat_per_kb` - The fee rate in satoshis per kilobyte
    ///
    /// # Returns
    ///
    /// * `FeeFilter` - A new FeeFilter message with the specified fee rate
    pub fn from_sat_per_kb(sat_per_kb: u64) -> Self {
        Self::new(sat_per_kb)
    }

    /// Gets the fee rate as satoshis per kilobyte.
    ///
    /// This is a convenience method that makes it clear the unit being used.
    ///
    /// # Returns
    ///
    /// * `u64` - The fee rate in satoshis per kilobyte
    pub fn as_sat_per_kb(&self) -> u64 {
        self.feerate
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::io::Cursor;

    use super::*;
    use crate::{
        blockdata::block::BitcoinHeader,
        client::{Connection, ConnectionManager, Message, network::NetworkMessage},
        consensus::{Decodable, Encodable},
        network::Network,
    };

    #[test]
    fn test_feefilter_new() {
        let feefilter = FeeFilter::new(1000);
        assert_eq!(feefilter.feerate, 1000);
    }

    #[test]
    fn test_feefilter_accessors() {
        let feefilter = FeeFilter::new(5000);
        assert_eq!(feefilter.feerate(), 5000);
    }

    #[test]
    fn test_feefilter_set_feerate() {
        let mut feefilter = FeeFilter::new(1000);
        feefilter.set_feerate(2000);
        assert_eq!(feefilter.feerate(), 2000);
    }

    #[test]
    fn test_feefilter_from_sat_per_kb() {
        let feefilter = FeeFilter::from_sat_per_kb(48508);
        assert_eq!(feefilter.feerate(), 48508);
    }

    #[test]
    fn test_feefilter_as_sat_per_kb() {
        let feefilter = FeeFilter::new(48508);
        assert_eq!(feefilter.as_sat_per_kb(), 48508);
    }

    #[test]
    fn test_feefilter_serialization_roundtrip() {
        let original = FeeFilter::new(48508);

        // Test serialization
        let mut encoded = Vec::new();
        original.consensus_encode(&mut encoded).unwrap();

        // Test deserialization
        let mut cursor = std::io::Cursor::new(&encoded);
        let decoded = FeeFilter::consensus_decode(&mut cursor).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_feefilter_serialization_with_known_values() {
        // Test with the example from the task: 48,508 satoshis per kilobyte
        let feefilter = FeeFilter::new(48508);

        let mut encoded = Vec::new();
        feefilter.consensus_encode(&mut encoded).unwrap();

        // Should be 8 bytes for the feerate (u64 in little-endian)
        assert_eq!(encoded.len(), 8);

        // Check the little-endian representation of 48508
        // 48508 = 0xBD7C, so in little-endian it should be [0x7C, 0xBD, 0x00, 0x00,
        // 0x00, 0x00, 0x00, 0x00]
        let expected_bytes = [0x7C, 0xBD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(encoded.as_slice(), expected_bytes);
    }

    #[test]
    fn test_feefilter_serialization_with_zero() {
        let feefilter = FeeFilter::new(0);

        let mut encoded = Vec::new();
        feefilter.consensus_encode(&mut encoded).unwrap();

        // Should be 8 bytes of zeros
        assert_eq!(encoded.len(), 8);
        assert_eq!(encoded, vec![0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_feefilter_serialization_with_max_value() {
        let feefilter = FeeFilter::new(u64::MAX);

        let mut encoded = Vec::new();
        feefilter.consensus_encode(&mut encoded).unwrap();

        // Should be 8 bytes of 0xFF
        assert_eq!(encoded.len(), 8);
        assert_eq!(
            encoded,
            vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        );
    }

    #[test]
    fn test_feefilter_clone_and_equality() {
        let feefilter = FeeFilter::new(1000);
        let clone = feefilter.clone();

        assert_eq!(feefilter, clone);
    }

    #[test]
    fn test_feefilter_inequality() {
        let feefilter1 = FeeFilter::new(1000);
        let feefilter2 = FeeFilter::new(2000);

        assert_ne!(feefilter1, feefilter2);
    }

    #[test]
    fn test_feefilter_message_serialization() {
        // Create a FeeFilter message with the example value from the task: 48,508
        // sat/kB
        let feefilter = FeeFilter::new(48508);

        // Test serialization to bytes
        let mut serialized = Vec::new();
        feefilter.consensus_encode(&mut serialized).unwrap();

        // Verify the serialized bytes match the expected little-endian representation
        // 48,508 = 0xBD7C, so in little-endian it should be [0x7C, 0xBD, 0x00, 0x00,
        // 0x00, 0x00, 0x00, 0x00]
        let expected_bytes = [0x7C, 0xBD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(serialized.as_slice(), expected_bytes);

        // Test deserialization
        let mut cursor = Cursor::new(&serialized);
        let deserialized = FeeFilter::consensus_decode(&mut cursor).unwrap();

        // Verify the deserialized value matches the original
        assert_eq!(deserialized.feerate(), 48508);
        assert_eq!(deserialized, feefilter);
    }

    #[test]
    fn test_feefilter_in_connection_enum() {
        // Create a FeeFilter message
        let feefilter = FeeFilter::new(48508);

        // Convert it to a Connection enum variant
        let connection_msg: Connection = feefilter.into();

        // Verify it's correctly stored as a FeeFilter variant
        match connection_msg {
            Connection::FeeFilter(f) => {
                assert_eq!(f.feerate(), 48508);
            }
            _ => panic!("Expected FeeFilter variant"),
        }
    }

    #[test]
    fn test_feefilter_in_message_enum() {
        // Create a FeeFilter message
        let feefilter = FeeFilter::new(48508);

        // Convert it to a Message enum
        let message: Message<BitcoinHeader> = Message::Connection(Connection::FeeFilter(feefilter));

        // Verify it's correctly stored as a Connection::FeeFilter variant
        match message {
            Message::Connection(Connection::FeeFilter(f)) => {
                assert_eq!(f.feerate(), 48508);
            }
            _ => panic!("Expected Connection::FeeFilter variant"),
        }
    }

    #[test]
    fn test_feefilter_network_message() {
        // Create a connection manager for testnet
        let manager = ConnectionManager::for_network(Network::Testnet);

        // Create a FeeFilter message
        let feefilter = FeeFilter::new(48508);
        let message: Message<BitcoinHeader> = Message::Connection(Connection::FeeFilter(feefilter));

        // Create a network message
        let network_msg = NetworkMessage::new(manager.magic(), message);
        assert!(network_msg.is_ok());

        let network_msg = network_msg.unwrap();

        // Verify the command is "feefilter"
        assert_eq!(network_msg.header.command.to_string(), "feefilter");

        // Serialize the network message to bytes
        let bytes = network_msg.to_bytes();
        assert!(bytes.is_ok());
        let bytes = bytes.unwrap();

        // Verify the payload contains the expected feerate
        // The payload should start after the 24-byte header
        if bytes.len() >= 32 {
            // 24-byte header + 8-byte payload
            let payload = &bytes[24..32];
            let expected_payload = [0x7C, 0xBD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            assert_eq!(payload, expected_payload);
        } else {
            panic!("Network message too short");
        }
    }

    #[test]
    fn test_feefilter_deserialization_from_bytes() {
        // Test with the example hex from the task: 7cbd000000000000
        let hex_bytes = [0x7C, 0xBD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        // Deserialize the bytes
        let mut cursor = Cursor::new(&hex_bytes);
        let feefilter = FeeFilter::consensus_decode(&mut cursor).unwrap();

        // Verify the fee rate is 48,508 satoshis per kilobyte
        assert_eq!(feefilter.feerate(), 48508);
    }

    #[test]
    fn test_feefilter_various_values() {
        // Test with various fee rates
        let test_values = [0, 1, 1000, 48508, 100000, u64::MAX];

        for &feerate in &test_values {
            let feefilter = FeeFilter::new(feerate);

            // Serialize
            let mut serialized = Vec::new();
            feefilter.consensus_encode(&mut serialized).unwrap();

            // Deserialize
            let mut cursor = Cursor::new(&serialized);
            let deserialized = FeeFilter::consensus_decode(&mut cursor).unwrap();

            // Verify round-trip
            assert_eq!(deserialized.feerate(), feerate);
            assert_eq!(deserialized, feefilter);
        }
    }

    #[test]
    fn test_feefilter_convenience_methods() {
        // Test the convenience methods
        let feefilter = FeeFilter::from_sat_per_kb(48508);
        assert_eq!(feefilter.as_sat_per_kb(), 48508);

        // Test setting the fee rate
        let mut feefilter = FeeFilter::new(1000);
        feefilter.set_feerate(2000);
        assert_eq!(feefilter.feerate(), 2000);
    }
}
