use super::inventory::{Inventory, InventoryList};
use alpha_p2p_derive::ConsensusEncoding;

/// Requests one or more data objects from another node. The objects are requested by an
/// inventory, which the requesting node typically received previously by way of an `inv`
/// message.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, ConsensusEncoding)]
pub struct GetData {
    /// The number of inventory vectors being requested.
    inventories: InventoryList,
}

impl GetData {
    /// Creates a new `GetData` message with the given inventories.
    pub fn new(inventories: Vec<Inventory>) -> Self {
        Self {
            inventories: InventoryList::new(inventories),
        }
    }

    /// Returns the list of inventories being requested.
    pub fn inventories(&self) -> &[Inventory] {
        self.inventories.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockdata::{block::BlockHash, transaction::Txid};
    use crate::consensus::{Decodable, Encodable};
    use crate::util::test_util::hex_to_hash;

    #[test]
    fn test_get_data_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let txid: Txid =
            hex_to_hash("de55ffd709ac1f5dc509a0925d0b1fc442ca034f224732e429081da1b621f55a")?;
        let block_hash: BlockHash =
            hex_to_hash("00000000000000000007878ec04bb2543ee2c5f9ce6d8b9c8d2d41a5b17db6a6")?;

        let original = GetData::new(vec![
            Inventory::Transaction(txid),
            Inventory::Block(block_hash),
        ]);

        // Test that the public API works
        assert_eq!(original.inventories().len(), 2);
        assert_eq!(
            original.inventories().first(),
            Some(&Inventory::Transaction(txid))
        );
        assert_eq!(
            original.inventories().get(1),
            Some(&Inventory::Block(block_hash))
        );

        // Test encoding/decoding integration
        let mut encoded = Vec::new();
        original.consensus_encode(&mut encoded)?;

        let mut cursor = std::io::Cursor::new(&encoded);
        let decoded = GetData::consensus_decode(&mut cursor)?;

        assert_eq!(original, decoded);

        Ok(())
    }

    #[test]
    fn test_get_data_empty() -> Result<(), Box<dyn std::error::Error>> {
        let get_data = GetData::new(vec![]);
        assert_eq!(get_data.inventories().len(), 0);

        // Verify it can be encoded/decoded
        let mut encoded = Vec::new();
        get_data.consensus_encode(&mut encoded)?;

        let mut cursor = std::io::Cursor::new(&encoded);
        let decoded = GetData::consensus_decode(&mut cursor)?;

        assert_eq!(get_data, decoded);

        Ok(())
    }
}
