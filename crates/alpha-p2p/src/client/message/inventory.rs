//! Module for handling inventory vectors in Bitcoin P2P consensus messages.
//!
//! This module defines the `Inventory` enum, which represents different types of inventory
//! items that can be advertised or requested between peers. It is used in network messages
//! such as `inv` and `getdata`.
//!
//! ## Inventory Types
//!
//! Each variant includes a 4-byte `inv_type` field and a 32-byte hash. The supported types are:
//!
//! - `Transaction`: A plain transaction (Txid).
//! - `Block`: A full block header.
//! - `FilteredBlock`: A block header requested as a `merkleblock` (requires bloom filter).
//! - `CompactBlock`: A block header requested as a `cmpctblock`.
//! - `WitnessTransaction`: A transaction that includes witness data.
//! - `WitnessBlock`: A block that includes witness data in its transactions.
//! - `FilteredWitnessBlock`: Reserved for future use.
//! - `Unknown`: A fallback for unrecognized inventory types.
//!
//! ## Encoding Format
//!
//! The consensus encoding format serializes each `Inventory` item as:
//!
//! - A 4-byte little-endian `inv_type`.
//! - A 32-byte hash.
//!
//! ## Usage
//!
//! The `Inventory` enum is primarily used in message handling logic to:
//!
//! - Advertise known blocks or transactions (`inv` message).
//! - Request missing data (`getdata` message).
//! - Support modern P2P features like witness and compact blocks.
//!
//! # Errors
//!
//! The `consensus_decode` implementation propagates parsing errors, such as malformed data.
use crate::blockdata::block::BlockHash;
use crate::blockdata::transaction::Txid;
use crate::consensus::encode::VarInt;
use crate::consensus::{Decodable, Encodable};
use crate::hashes::Hash;

/// A list of inventory items for consensus encoding
#[derive(Default, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct InventoryList(pub Vec<Inventory>);

#[allow(dead_code)]
impl InventoryList {
    /// Constructs a new `InventoryList` from the given vector of `Inventory` items.
    pub fn new(inventories: Vec<Inventory>) -> Self {
        Self(inventories)
    }

    /// Returns the number of inventory items contained in the list.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the list contains no inventory items.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Removes all inventory items from the list, resetting its length to zero.
    pub fn clear(&mut self) {
        self.0.clear();
    }

    /// Returns a reference to the first inventory item, or `None` if the list is empty.
    pub fn first(&self) -> Option<&Inventory> {
        self.0.first()
    }

    /// Returns a reference to the last inventory item, or `None` if the list is empty.
    pub fn last(&self) -> Option<&Inventory> {
        self.0.last()
    }

    /// Returns a mutable reference to the first inventory item, or `None` if the list is empty.
    pub fn first_mut(&mut self) -> Option<&mut Inventory> {
        self.0.first_mut()
    }

    /// Returns a mutable reference to the last inventory item, or `None` if the list is empty.
    pub fn last_mut(&mut self) -> Option<&mut Inventory> {
        self.0.last_mut()
    }

    /// Appends an `Inventory` item to the end of the list.
    pub fn push(&mut self, inventory: Inventory) {
        self.0.push(inventory);
    }

    /// Removes and returns the last `Inventory` item, or `None` if the list is empty.
    pub fn pop(&mut self) -> Option<Inventory> {
        self.0.pop()
    }

    /// Inserts an `Inventory` item at the specified index, shifting all subsequent elements to the right.
    pub fn insert(&mut self, index: usize, inventory: Inventory) {
        self.0.insert(index, inventory);
    }

    /// Removes and returns the `Inventory` item at the specified index, shifting all subsequent elements to the left.
    pub fn remove(&mut self, index: usize) -> Inventory {
        self.0.remove(index)
    }

    /// Returns an immutable iterator over the `Inventory` items in the list.
    pub fn iter(&self) -> std::slice::Iter<'_, Inventory> {
        self.0.iter()
    }

    /// Returns a mutable iterator over the `Inventory` items in the list.
    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, Inventory> {
        self.0.iter_mut()
    }

    /// Consumes the `InventoryList`, returning the underlying vector of `Inventory` items.
    pub fn into_vec(self) -> Vec<Inventory> {
        self.0
    }

    /// Returns a slice view of the underlying vector of `Inventory` items.
    pub fn as_slice(&self) -> &[Inventory] {
        &self.0
    }
}

impl From<Vec<Inventory>> for InventoryList {
    fn from(inventories: Vec<Inventory>) -> Self {
        Self::new(inventories)
    }
}

impl IntoIterator for InventoryList {
    type Item = Inventory;
    type IntoIter = std::vec::IntoIter<Inventory>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a InventoryList {
    type Item = &'a Inventory;
    type IntoIter = std::slice::Iter<'a, Inventory>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl FromIterator<Inventory> for InventoryList {
    fn from_iter<I: IntoIterator<Item = Inventory>>(iter: I) -> Self {
        Self::new(iter.into_iter().collect())
    }
}

impl Extend<Inventory> for InventoryList {
    fn extend<I: IntoIterator<Item = Inventory>>(&mut self, iter: I) {
        self.0.extend(iter);
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "Length calculations can't overflow in practice"
)]
impl Encodable for InventoryList {
    fn consensus_encode<W: crate::io::Write + ?Sized>(
        &self,
        w: &mut W,
    ) -> Result<usize, crate::io::Error> {
        let mut len = 0;
        len += VarInt::from(self.0.len()).consensus_encode(w)?;
        for item in &self.0 {
            len += item.consensus_encode(w)?;
        }
        Ok(len)
    }
}

impl Decodable for InventoryList {
    fn consensus_decode<R: crate::io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, crate::consensus::EncodeDecodeError> {
        let len = VarInt::consensus_decode(r)?.0;

        if len > crate::consensus::MAX_VEC_SIZE as u64 {
            return Err(crate::consensus::EncodeDecodeError::ParseFailed(
                "Vector too large, exceeds MAX_VEC_SIZE",
            ));
        }

        #[allow(clippy::cast_possible_truncation, reason = "Already pre-checked")]
        let mut ret = Vec::with_capacity(len as usize);
        for _ in 0..len {
            ret.push(Inventory::consensus_decode(r)?);
        }
        Ok(InventoryList(ret))
    }
}

/// Inventory vector types used in Bitcoin P2P protocol.
///
/// Inventory vectors are used to advertise and request data (blocks, transactions, etc.)
/// between peers in the Bitcoin network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Inventory {
    /// The hash is a `Txid`.
    Transaction(Txid),
    /// The hash is a block header.
    Block(BlockHash),
    /// The hash is a block header, like Block.
    /// When used in a `getdata` message, the corresponding address is a `merkleblock` message,
    /// not a `block` message (but only works if a bloom filter had been configured).
    ///
    /// Only used in `getdata` messages.
    FilteredBlock(BlockHash),
    /// The hash is a block header, like Block.
    /// When used in a `getdata` message, the corresponding address is a `cmpactblock` message,
    /// not a `block` message.
    ///
    /// Only used in `getdata` messages.
    CompactBlock(BlockHash),
    /// The hash is a `Txid`. When used in a `getdata` message, the corresponding response is a
    /// transaction message if the witness structure is not stripped. The witness serialization
    /// will be used.
    ///
    /// Only used in `getdata` messages.
    WitnessTransaction(Txid),
    /// The hash is a block header. When used in a `getdata` message, the corresponding response
    /// is a block message with transactions that have a witness using witness serialization.
    ///
    /// Only used in `getdata` messages.
    WitnessBlock(BlockHash),
    /// Reserved for future use, not currently implemented into any protocol.
    FilteredWitnessBlock(BlockHash),
    /// If an inventory received is unknown, it is stored as this variant for later reporting or
    /// other purposes.
    ///
    /// # Fields
    ///
    /// * `inv_type` - The inventory type value that was not recognized
    /// * `hash` - The hash associated with the unknown inventory type
    Unknown {
        /// The inventory type value that was not recognized
        inv_type: u32,
        /// The hash associated with the unknown inventory type
        hash: [u8; 32],
    },
}

impl Inventory {
    fn inv_type(&self) -> u32 {
        match self {
            Inventory::Transaction(_) => 1,
            Inventory::Block(_) => 2,
            Inventory::FilteredBlock(_) => 3,
            Inventory::CompactBlock(_) => 4,
            Inventory::WitnessTransaction(_) => 0x40000001,
            Inventory::WitnessBlock(_) => 0x40000002,
            Inventory::FilteredWitnessBlock(_) => 0x40000003,
            Inventory::Unknown { inv_type, .. } => *inv_type,
        }
    }

    fn hash_bytes(&self) -> &[u8; 32] {
        match self {
            Inventory::Transaction(hash) => hash.as_byte_array(),
            Inventory::Block(hash) => hash.as_byte_array(),
            Inventory::FilteredBlock(hash) => hash.as_byte_array(),
            Inventory::CompactBlock(hash) => hash.as_byte_array(),
            Inventory::WitnessTransaction(hash) => hash.as_byte_array(),
            Inventory::WitnessBlock(hash) => hash.as_byte_array(),
            Inventory::FilteredWitnessBlock(hash) => hash.as_byte_array(),
            Inventory::Unknown { hash, .. } => hash,
        }
    }

    fn as_parts(&self) -> (u32, &[u8; 32]) {
        (self.inv_type(), self.hash_bytes())
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "It can't possibly overflow, as the values are expected to be small."
)]
impl Encodable for Inventory {
    fn consensus_encode<W: crate::io::Write + ?Sized>(
        &self,
        w: &mut W,
    ) -> Result<usize, crate::io::Error> {
        let (inv_type, hash) = self.as_parts();
        let mut len = 0;
        len += inv_type.consensus_encode(w)?;
        len += hash.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for Inventory {
    fn consensus_decode<R: crate::io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, crate::consensus::EncodeDecodeError> {
        let inv_type: u32 = Decodable::consensus_decode(r)?;
        let hash: [u8; 32] = Decodable::consensus_decode(r)?;
        Ok(match inv_type {
            1 => Inventory::Transaction(Txid::from_byte_array(hash)),
            2 => Inventory::Block(BlockHash::from_byte_array(hash)),
            3 => Inventory::FilteredBlock(BlockHash::from_byte_array(hash)),
            4 => Inventory::CompactBlock(BlockHash::from_byte_array(hash)),
            0x40000001 => Inventory::WitnessTransaction(Txid::from_byte_array(hash)),
            0x40000002 => Inventory::WitnessBlock(BlockHash::from_byte_array(hash)),
            0x40000003 => Inventory::FilteredWitnessBlock(BlockHash::from_byte_array(hash)),
            _ => Inventory::Unknown { inv_type, hash },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{hex_to_blockhash, hex_to_txid};

    #[test]
    fn test_inventory_encode() -> Result<(), Box<dyn std::error::Error>> {
        let expected = hex::decode(
            "01000000\
            de55ffd709ac1f5dc509a0925d0b1fc4\
            42ca034f224732e429081da1b621f55a",
        )?;

        let txid: Txid =
            hex_to_txid("de55ffd709ac1f5dc509a0925d0b1fc442ca034f224732e429081da1b621f55a")?;

        let inv = Inventory::Transaction(txid);
        let mut encoded = Vec::new();
        let _bytes_written = inv.consensus_encode(&mut encoded)?;

        assert_eq!(expected, encoded);

        Ok(())
    }

    #[test]
    fn test_inventory_decode() -> Result<(), Box<dyn std::error::Error>> {
        let expected_data = hex::decode(
            "01000000\
            de55ffd709ac1f5dc509a0925d0b1fc4\
            42ca034f224732e429081da1b621f55a",
        )?;

        let mut cursor = std::io::Cursor::new(&expected_data);
        let expected_inv = Inventory::consensus_decode(&mut cursor)?;

        let expected_txid: Txid =
            hex_to_txid("de55ffd709ac1f5dc509a0925d0b1fc442ca034f224732e429081da1b621f55a")?;

        assert_eq!(expected_inv, Inventory::Transaction(expected_txid));

        Ok(())
    }

    #[test]
    fn test_inventory_list_encode_single() -> Result<(), Box<dyn std::error::Error>> {
        let txid: Txid =
            hex_to_txid("de55ffd709ac1f5dc509a0925d0b1fc442ca034f224732e429081da1b621f55a")?;

        let inventory_list = InventoryList::new(vec![Inventory::Transaction(txid)]);

        let mut encoded = Vec::new();
        let _bytes_written = inventory_list.consensus_encode(&mut encoded)?;

        // Expected: VarInt(1) + single inventory item
        let expected = hex::decode(
            "01\
            01000000\
            de55ffd709ac1f5dc509a0925d0b1fc4\
            42ca034f224732e429081da1b621f55a",
        )?;

        assert_eq!(expected, encoded);

        Ok(())
    }

    #[test]
    fn test_inventory_list_decode_single() -> Result<(), Box<dyn std::error::Error>> {
        let expected_data = hex::decode(
            "01\
            01000000\
            de55ffd709ac1f5dc509a0925d0b1fc4\
            42ca034f224732e429081da1b621f55a",
        )?;

        let mut cursor = std::io::Cursor::new(&expected_data);
        let decoded_list = InventoryList::consensus_decode(&mut cursor)?;

        let expected_txid: Txid =
            hex_to_txid("de55ffd709ac1f5dc509a0925d0b1fc442ca034f224732e429081da1b621f55a")?;

        assert_eq!(decoded_list.0.len(), 1);
        assert_eq!(
            *decoded_list.0.first().ok_or("First doesn't exist")?,
            Inventory::Transaction(expected_txid)
        );

        Ok(())
    }

    #[test]
    fn test_inventory_list_encode_multiple() -> Result<(), Box<dyn std::error::Error>> {
        let txid: Txid =
            hex_to_txid("de55ffd709ac1f5dc509a0925d0b1fc442ca034f224732e429081da1b621f55a")?;
        let block_hash: BlockHash =
            hex_to_blockhash("00000000000000000007878ec04bb2543ee2c5f9ce6d8b9c8d2d41a5b17db6a6")?;

        let inventory_list = InventoryList::new(vec![
            Inventory::Transaction(txid),
            Inventory::Block(block_hash),
        ]);

        let mut encoded = Vec::new();
        let _bytes_written = inventory_list.consensus_encode(&mut encoded)?;

        // Expected: VarInt(2) + two inventory items
        let expected = hex::decode(
            "02\
            01000000\
            de55ffd709ac1f5dc509a0925d0b1fc4\
            42ca034f224732e429081da1b621f55a\
            02000000\
            00000000000000000007878ec04bb254\
            3ee2c5f9ce6d8b9c8d2d41a5b17db6a6",
        )?;

        assert_eq!(expected, encoded);

        Ok(())
    }

    #[test]
    fn test_inventory_list_decode_multiple() -> Result<(), Box<dyn std::error::Error>> {
        let expected_data = hex::decode(
            "02\
            01000000\
            de55ffd709ac1f5dc509a0925d0b1fc4\
            42ca034f224732e429081da1b621f55a\
            02000000\
            00000000000000000007878ec04bb254\
            3ee2c5f9ce6d8b9c8d2d41a5b17db6a6",
        )?;

        let mut cursor = std::io::Cursor::new(&expected_data);
        let decoded_list = InventoryList::consensus_decode(&mut cursor)?;

        let expected_txid: Txid =
            hex_to_txid("de55ffd709ac1f5dc509a0925d0b1fc442ca034f224732e429081da1b621f55a")?;
        let expected_block: BlockHash =
            hex_to_blockhash("00000000000000000007878ec04bb2543ee2c5f9ce6d8b9c8d2d41a5b17db6a6")?;

        assert_eq!(decoded_list.0.len(), 2);
        assert_eq!(
            *decoded_list.0.first().ok_or("First doesn't exist")?,
            Inventory::Transaction(expected_txid)
        );
        assert_eq!(
            *decoded_list.0.get(1).ok_or("Index 1 doesn't exist")?,
            Inventory::Block(expected_block)
        );

        Ok(())
    }

    #[test]
    fn test_inventory_list_encode_empty() -> Result<(), Box<dyn std::error::Error>> {
        let inventory_list = InventoryList::new(vec![]);

        let mut encoded = Vec::new();
        let _bytes_written = inventory_list.consensus_encode(&mut encoded)?;

        // Expected: Just VarInt(0)
        let expected = vec![0x00];

        assert_eq!(expected, encoded);

        Ok(())
    }

    #[test]
    fn test_inventory_list_decode_empty() -> Result<(), Box<dyn std::error::Error>> {
        let expected_data = vec![0x00];

        let mut cursor = std::io::Cursor::new(&expected_data);
        let decoded_list = InventoryList::consensus_decode(&mut cursor)?;

        assert_eq!(decoded_list.0.len(), 0);
        assert!(decoded_list.0.is_empty());

        Ok(())
    }

    #[test]
    fn test_inventory_list_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let txid: Txid =
            hex_to_txid("de55ffd709ac1f5dc509a0925d0b1fc442ca034f224732e429081da1b621f55a")?;
        let block_hash: BlockHash =
            hex_to_blockhash("00000000000000000007878ec04bb2543ee2c5f9ce6d8b9c8d2d41a5b17db6a6")?;

        let original_list = InventoryList::new(vec![
            Inventory::Transaction(txid),
            Inventory::Block(block_hash),
            Inventory::WitnessTransaction(txid),
        ]);

        // Encode
        let mut encoded = Vec::new();
        let _bytes_written = original_list.consensus_encode(&mut encoded)?;

        // Decode
        let mut cursor = std::io::Cursor::new(&encoded);
        let decoded_list = InventoryList::consensus_decode(&mut cursor)?;

        // Verify roundtrip
        assert_eq!(original_list, decoded_list);

        Ok(())
    }

    #[test]
    fn test_inventory_list_conversions() -> Result<(), Box<dyn std::error::Error>> {
        let txid: Txid =
            hex_to_txid("de55ffd709ac1f5dc509a0925d0b1fc442ca034f224732e429081da1b621f55a")?;

        let original_vec = vec![Inventory::Transaction(txid)];

        // Test From<Vec<Inventory>>
        let inventory_list: InventoryList = original_vec.clone().into();
        assert_eq!(inventory_list.0, original_vec);

        // Test into_vec()
        let converted_vec = inventory_list.into_vec();
        assert_eq!(converted_vec, original_vec);

        // Test as_slice()
        let new_list = InventoryList::new(original_vec.clone());
        let slice = new_list.as_slice();
        assert_eq!(slice, &original_vec[..]);

        Ok(())
    }
}
