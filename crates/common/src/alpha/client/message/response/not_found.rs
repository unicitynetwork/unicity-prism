//! Not found response message types for the P2P protocol.
//!
//! This module contains the not found response message implementation, which is
//! used to send information about missing data from peers in response to
//! `getdata` requests.
//!
//! # Usage
//!
//! The `NotFound` message is sent when a peer requests data (like blocks or
//! transactions) that it doesn't have available. It contains the inventory
//! vectors of the requested items that were not found, allowing peers to
//! understand what data is missing.
//!
//! # Consensus Encoding
//!
//! The `NotFound` struct manually implements `Encodable` and `Decodable`
//! traits, allowing it to be encoded and decoded according to Bitcoin's
//! consensus rules.
//!
//! # Examples
//!
//! TODO: Add examples when the library is more mature.

use crate::alpha::{
    client::message::inventory::Inventory,
    consensus::{Decodable, Encodable},
};

/// Represents a not found response message in the P2P protocol.
///
/// A `NotFound` response is sent when a peer requests data (like blocks or
/// transactions) that it doesn't have available. It contains the inventory
/// vectors of the requested items that were not found.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NotFound {
    /// A list of inventory vectors representing the items that were not found.
    pub inventories: Vec<Inventory>,
}

impl NotFound {
    /// Creates a new `NotFound` response message with the specified
    /// inventories.
    ///
    /// # Arguments
    ///
    /// * `inventories` - A vector of inventory items that were not found.
    ///
    /// # Returns
    ///
    /// * `NotFound` - A new instance of the NotFound response message.
    pub fn new(inventories: Vec<Inventory>) -> Self {
        Self { inventories }
    }

    /// Returns the list of inventories in the response.
    ///
    /// # Returns
    ///
    /// * `&[Inventory]` - A slice of the inventories in the response.
    pub fn inventories(&self) -> &[Inventory] {
        &self.inventories
    }

    /// Returns the number of inventories in the response.
    ///
    /// # Returns
    ///
    /// * `usize` - The number of inventories in the response.
    pub fn len(&self) -> usize {
        self.inventories.len()
    }

    /// Checks if the response contains no inventories.
    ///
    /// # Returns
    ///
    /// * `bool` - True if the response contains no inventories, false
    ///   otherwise.
    pub fn is_empty(&self) -> bool {
        self.inventories.is_empty()
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "Won't fail on usize addition"
)]
impl Encodable for NotFound {
    fn consensus_encode<W: crate::alpha::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<usize, crate::alpha::io::Error> {
        let mut len = 0;
        // Encode the number of inventories as a VarInt
        len += crate::alpha::consensus::VarInt::from(self.inventories.len())
            .consensus_encode(writer)?;
        // Encode each inventory
        for inventory in &self.inventories {
            len += inventory.consensus_encode(writer)?;
        }
        Ok(len)
    }
}

#[allow(clippy::cast_possible_truncation, reason = "It will fit.")]
impl Decodable for NotFound {
    fn consensus_decode<R: crate::alpha::io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, crate::alpha::consensus::EncodeDecodeError> {
        // Decode the number of inventories as a VarInt
        let len = crate::alpha::consensus::VarInt::consensus_decode(reader)?.0;

        // Check that the length is within bounds
        if len > crate::alpha::consensus::MAX_VEC_SIZE as u64 {
            return Err(crate::alpha::consensus::EncodeDecodeError::ParseFailed(
                "Vector too large, exceeds MAX_VEC_SIZE",
            ));
        }

        // Create a vector to hold the inventories
        let mut inventories = Vec::with_capacity(len as usize);

        // Decode each inventory
        for _ in 0..len {
            inventories.push(Decodable::consensus_decode(reader)?);
        }

        Ok(NotFound { inventories })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alpha::{
        blockdata::{block::BlockHash, transaction::Txid},
        client::message::inventory::Inventory,
        consensus::{Decodable, Encodable},
        hashes::Hash,
    };

    #[test]
    fn test_not_found_new() {
        let txid = Txid::from_byte_array([0; 32]);
        let block_hash = BlockHash::from_byte_array([0; 32]);
        let inventories = vec![Inventory::Transaction(txid), Inventory::Block(block_hash)];

        let response = NotFound::new(inventories.clone());

        assert_eq!(response.inventories(), inventories.as_slice());
    }

    #[test]
    fn test_not_found_inventories_access() {
        let txid = Txid::from_byte_array([0; 32]);
        let block_hash = BlockHash::from_byte_array([0; 32]);
        let inventory1 = Inventory::Transaction(txid);
        let inventory2 = Inventory::Block(block_hash);
        let inventories = vec![inventory1, inventory2];

        let response = NotFound::new(inventories);

        assert_eq!(response.inventories(), &[inventory1, inventory2]);
    }

    #[test]
    fn test_not_found_len() {
        let txid = Txid::from_byte_array([0; 32]);
        let block_hash = BlockHash::from_byte_array([0; 32]);
        let inventories = vec![Inventory::Transaction(txid), Inventory::Block(block_hash)];

        let response = NotFound::new(inventories);

        assert_eq!(response.len(), 2);
    }

    #[test]
    fn test_not_found_is_empty() {
        let response = NotFound::new(vec![]);

        assert!(response.is_empty());

        let txid = Txid::from_byte_array([0; 32]);
        let response_with_inventories = NotFound::new(vec![Inventory::Transaction(txid)]);

        assert!(!response_with_inventories.is_empty());
    }

    #[test]
    fn test_not_found_round_trip() {
        let txid = Txid::from_byte_array([0; 32]);
        let block_hash = BlockHash::from_byte_array([0; 32]);
        let inventories = vec![Inventory::Transaction(txid), Inventory::Block(block_hash)];

        let original = NotFound::new(inventories);

        // Encode
        let mut encoded = Vec::new();
        original.consensus_encode(&mut encoded).unwrap();

        // Decode
        let mut cursor = std::io::Cursor::new(&encoded);
        let decoded = NotFound::consensus_decode(&mut cursor).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_not_found_equality() {
        let txid = Txid::from_byte_array([0; 32]);
        let block_hash = BlockHash::from_byte_array([0; 32]);
        let inventories1 = vec![Inventory::Transaction(txid), Inventory::Block(block_hash)];
        let inventories2 = vec![Inventory::Transaction(txid), Inventory::Block(block_hash)];

        let response1 = NotFound::new(inventories1);
        let response2 = NotFound::new(inventories2);

        // Same inventories should be equal
        assert_eq!(response1, response2);
    }

    #[test]
    fn test_not_found_equality_different_length() {
        let txid = Txid::from_byte_array([0; 32]);
        let block_hash = BlockHash::from_byte_array([0; 32]);
        let inventories1 = vec![Inventory::Transaction(txid)];
        let inventories2 = vec![Inventory::Transaction(txid), Inventory::Block(block_hash)];

        let response1 = NotFound::new(inventories1);
        let response2 = NotFound::new(inventories2);

        // Different length should not be equal
        assert_ne!(response1, response2);
    }
}
