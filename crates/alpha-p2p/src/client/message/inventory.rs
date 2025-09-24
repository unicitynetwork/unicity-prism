use crate::blockdata::block::BlockHash;
use crate::blockdata::transaction::Txid;
use crate::consensus::{Decodable, Encodable};
use crate::hashes::Hash;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
    Unknown { inv_type: u32, hash: [u8; 32] },
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
    use crate::util::test_util::hex_to_hash;

    #[test]
    fn test_inventory_encode() -> Result<(), Box<dyn std::error::Error>> {
        let expected = hex::decode(
            "01000000\
            de55ffd709ac1f5dc509a0925d0b1fc4\
            42ca034f224732e429081da1b621f55a",
        )?;

        let txid: Txid =
            hex_to_hash("de55ffd709ac1f5dc509a0925d0b1fc442ca034f224732e429081da1b621f55a")?;

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
            hex_to_hash("de55ffd709ac1f5dc509a0925d0b1fc442ca034f224732e429081da1b621f55a")?;

        assert_eq!(expected_inv, Inventory::Transaction(expected_txid));

        Ok(())
    }
}
