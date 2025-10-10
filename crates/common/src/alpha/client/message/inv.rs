//! Inventory message implementation for Bitcoin P2P protocol.
//!
//! This module defines the `Inv` message, which is used to advertise
//! known inventory (blocks, transactions, etc.) to peers in the Bitcoin network.

use crate::alpha::{
    client::message::inventory::InventoryList,
    consensus::{Decodable, Encodable},
    io::{Error as IoError, Write},
};

/// Inventory message used to advertise known objects to peers.
///
/// The inv message informs a peer about objects that this node has
/// available. The peer can then request these objects using a getdata
/// message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inv(pub InventoryList);

impl Inv {
    /// Creates a new inv message with the given inventory list.
    pub fn new(inventory_list: InventoryList) -> Self {
        Self(inventory_list)
    }

    /// Gets a reference to the inventory list.
    pub fn inventory(&self) -> &InventoryList {
        &self.0
    }

    /// Gets a mutable reference to the inventory list.
    pub fn inventory_mut(&mut self) -> &mut InventoryList {
        &mut self.0
    }

    /// Consumes the inv message and returns the inventory list.
    pub fn into_inventory(self) -> InventoryList {
        self.0
    }
}

impl Encodable for Inv {
    fn consensus_encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, IoError> {
        self.0.consensus_encode(writer)
    }
}

impl Decodable for Inv {
    fn consensus_decode<R: crate::alpha::io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, crate::alpha::consensus::EncodeDecodeError> {
        let inventory_list = InventoryList::consensus_decode(reader)?;
        Ok(Inv(inventory_list))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alpha::{
        blockdata::{block::BlockHash, transaction::Txid},
        client::message::inventory::Inventory,
        util::{hex_to_blockhash, hex_to_txid},
    };

    #[test]
    fn test_inv_message_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let txid: Txid =
            hex_to_txid("de55ffd709ac1f5dc509a0925d0b1fc442ca034f224732e429081da1b621f55a")?;
        let block_hash: BlockHash =
            hex_to_blockhash("00000000000000000007878ec04bb2543ee2c5f9ce6d8b9c8d2d41a5b17db6a6")?;

        let inventory_list = InventoryList::new(vec![
            Inventory::Transaction(txid),
            Inventory::Block(block_hash),
        ]);

        let inv_message = Inv::new(inventory_list.clone());

        // Test encoding
        let mut encoded = Vec::new();
        let _bytes_written = inv_message.consensus_encode(&mut encoded)?;

        // Test decoding
        let mut cursor = std::io::Cursor::new(&encoded);
        let decoded = Inv::consensus_decode(&mut cursor)?;

        // Verify roundtrip
        assert_eq!(decoded.inventory(), &inventory_list);

        Ok(())
    }

    #[test]
    fn test_inv_message_empty() -> Result<(), Box<dyn std::error::Error>> {
        let inventory_list = InventoryList::new(vec![]);
        let inv_message = Inv::new(inventory_list);

        // Test encoding
        let mut encoded = Vec::new();
        let _bytes_written = inv_message.consensus_encode(&mut encoded)?;

        // Expected: Just VarInt(0)
        let expected = vec![0x00];
        assert_eq!(encoded, expected);

        // Test decoding
        let mut cursor = std::io::Cursor::new(&encoded);
        let decoded = Inv::consensus_decode(&mut cursor)?;

        assert_eq!(decoded.inventory().len(), 0);
        assert!(decoded.inventory().is_empty());

        Ok(())
    }

    #[test]
    fn test_inv_message_accessors() -> Result<(), Box<dyn std::error::Error>> {
        let txid: Txid =
            hex_to_txid("de55ffd709ac1f5dc509a0925d0b1fc442ca034f224732e429081da1b621f55a")?;
        let inventory_list = InventoryList::new(vec![Inventory::Transaction(txid)]);
        let mut inv_message = Inv::new(inventory_list.clone());

        // Test inventory() accessor
        assert_eq!(inv_message.inventory(), &inventory_list);

        // Test inventory_mut() accessor
        let new_txid: Txid =
            hex_to_txid("a1b2c3d4e5f60708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021")?;
        inv_message.inventory_mut().push(Inventory::Transaction(new_txid));
        assert_eq!(inv_message.inventory().len(), 2);

        // Test into_inventory() accessor
        let retrieved_inventory = inv_message.into_inventory();
        assert_eq!(retrieved_inventory.len(), 2);

        Ok(())
    }
}