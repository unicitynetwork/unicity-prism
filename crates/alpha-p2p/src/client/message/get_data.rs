//! Requests one or more data objects from another node. The objects are requested by an
//! inventory, which the requesting node typically received previously by way of an `inv`
//! message.
//!
//! This struct implements the `GetData` message type used in the Alpha protocol to request
//! specific data objects (like blocks or transactions) from peer nodes.
//!
//! The message contains a list of inventory vectors that specify which objects are being requested.
//! Each inventory vector specifies the type and hash of the object to be retrieved.
//!
//! # Example
//!
//! ```ignore
//! use alpha_p2p::client::message::{GetData, inventory::{Inventory, InventoryList}};
//! use alpha_p2p::blockdata::transaction::Txid;
//! use alpha_p2p::blockdata::block::BlockHash;
//! use hex;
//!
//! let txid: Txid = hex_to_hash("de55ffd709ac1f5dc509a0925d0b1fc442ca034f224732e429081da1b621f55a")?;
//! let block_hash: BlockHash = hex_to_hash("00000000000000000007878ec04bb2543ee2c5f9ce6d8b9c8d2d41a5b17db6a6")?;
//!
//! let get_data = GetData::new(vec![
//!     Inventory::Transaction(txid),
//!     Inventory::Block(block_hash),
//! ]);
//!
//! assert_eq!(get_data.inventories().len(), 2);
//! ```

pub(crate) use super::inventory::{Inventory, InventoryList};
use alpha_p2p_derive::ConsensusCodec;

/// Requests one or more data objects from another node. The objects are requested by an
/// inventory, which the requesting node typically received previously by way of an `inv`
/// message.
///
/// This struct implements the `GetData` message type used in the Alpha protocol to request
/// specific data objects (like blocks or transactions) from peer nodes.
///
/// The message contains a list of inventory vectors that specify which objects are being requested.
/// Each inventory vector specifies the type and hash of the object to be retrieved.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, ConsensusCodec)]
pub struct GetData {
    /// The list of inventory vectors being requested.
    inventories: InventoryList,
}

impl GetData {
    /// Creates a new `GetData` message with the given inventories.
    ///
    /// # Arguments
    ///
    /// * `inventories` - A vector of inventory items to be requested.
    ///
    /// # Returns
    ///
    /// * `GetData` - A new instance of the GetData message.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use alpha_p2p::client::message::{GetData, inventory::{Inventory, InventoryList}};
    /// use alpha_p2p::blockdata::transaction::Txid;
    /// use alpha_p2p::blockdata::block::BlockHash;
    /// use hex;
    ///
    /// let txid: Txid = hex_to_hash("de55ffd709ac1f5dc509a0925d0b1fc442ca034f224732e429081da1b621f55a")?;
    /// let block_hash: BlockHash = hex_to_hash("00000000000000000007878ec04bb2543ee2c5f9ce6d8b9c8d2d41a5b17db6a6")?;
    ///
    /// let get_data = GetData::new(vec![
    ///     Inventory::Transaction(txid),
    ///     Inventory::Block(block_hash),
    /// ]);
    ///
    /// assert_eq!(get_data.inventories().len(), 2);
    /// ```
    pub fn new(inventories: Vec<Inventory>) -> Self {
        Self {
            inventories: InventoryList::new(inventories),
        }
    }

    /// Returns the list of inventories being requested.
    ///
    /// # Returns
    ///
    /// * `&[Inventory]` - A slice of the inventory items being requested.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use alpha_p2p::client::message::{GetData, inventory::{Inventory, InventoryList}};
    /// use alpha_p2p::blockdata::transaction::Txid;
    /// use alpha_p2p::blockdata::block::BlockHash;
    /// use hex;
    ///
    /// let txid: Txid = hex_to_hash("de55ffd709ac1f5dc509a0925d0b1fc442ca034f224732e429081da1b621f55a")?;
    /// let block_hash: BlockHash = hex_to_hash("00000000000000000007878ec04bb2543ee2c5f9ce6d8b9c8d2d41a5b17db6a6")?;
    ///
    /// let get_data = GetData::new(vec![
    ///     Inventory::Transaction(txid),
    ///     Inventory::Block(block_hash),
    /// ]);
    ///
    /// assert_eq!(get_data.inventories().len(), 2);
    /// ```
    pub fn inventories(&self) -> &[Inventory] {
        self.inventories.as_slice()
    }

    /// Returns the number of inventory items being requested.
    ///
    /// # Returns
    ///
    /// * `usize` - The number of inventory items in the request.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use alpha_p2p::client::message::{GetData, inventory::{Inventory, InventoryList}};
    /// use alpha_p2p::blockdata::transaction::Txid;
    /// use alpha_p2p::blockdata::block::BlockHash;
    /// use hex;
    ///
    /// let txid: Txid = hex_to_hash("de55ffd709ac1f5dc509a0925d0b1fc442ca034f224732e429081da1b621f55a")?;
    /// let block_hash: BlockHash = hex_to_hash("00000000000000000007878ec04bb2543ee2c5f9ce6d8b9c8d2d41a5b17db6a6")?;
    ///
    /// let get_data = GetData::new(vec![
    ///     Inventory::Transaction(txid),
    ///     Inventory::Block(block_hash),
    /// ]);
    ///
    /// assert_eq!(get_data.len(), 2);
    /// ```
    pub fn len(&self) -> usize {
        self.inventories.len()
    }

    /// Checks if the list of inventories is empty.
    ///
    /// # Returns
    ///
    /// * `bool` - True if the list of inventories is empty, false otherwise.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use alpha_p2p::client::message::{GetData, inventory::{Inventory, InventoryList}};
    ///
    /// let get_data = GetData::new(vec![]);
    /// assert!(get_data.is_empty());
    ///
    /// let get_data = GetData::new(vec![Inventory::Transaction(Default::default())]);
    /// assert!(!get_data.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.inventories.is_empty()
    }

    /// Adds an inventory item to the list of requested inventories.
    ///
    /// # Arguments
    ///
    /// * `inventory` - The inventory item to be added.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use alpha_p2p::client::message::{GetData, inventory::{Inventory, InventoryList}};
    /// use alpha_p2p::blockdata::transaction::Txid;
    /// use alpha_p2p::blockdata::block::BlockHash;
    /// use hex;
    ///
    /// let txid: Txid = hex_to_hash("de55ffd709ac1f5dc509a0925d0b1fc442ca034f224732e429081da1b621f55a")?;
    /// let block_hash: BlockHash = hex_to_hash("00000000000000000007878ec04bb2543ee2c5f9ce6d8b9c8d2d41a5b17db6a6")?;
    ///
    /// let mut get_data = GetData::new(vec![]);
    /// get_data.add_inventory(Inventory::Transaction(txid));
    /// get_data.add_inventory(Inventory::Block(block_hash));
    ///
    /// assert_eq!(get_data.inventories().len(), 2);
    /// ```
    pub fn add_inventory(&mut self, inventory: Inventory) {
        self.inventories.0.push(inventory);
    }

    /// Creates an empty `GetData` message.
    ///
    /// # Returns
    ///
    /// * `GetData` - A new instance of the GetData message with an empty list of inventories.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use alpha_p2p::client::message::{GetData, inventory::{Inventory, InventoryList}};
    ///
    /// let get_data = GetData::empty();
    /// assert_eq!(get_data.inventories().len(), 0);
    /// ```
    pub fn empty() -> Self {
        Self {
            inventories: InventoryList::new(vec![]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockdata::{block::BlockHash, transaction::Txid};
    use crate::consensus::{Decodable, Encodable};
    use crate::util::hex_to_hash;

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
