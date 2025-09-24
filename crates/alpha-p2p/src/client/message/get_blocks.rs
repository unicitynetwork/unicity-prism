use crate::blockdata::block::BlockHash;
use crate::hashes::Hash;
use alpha_p2p_derive::ConsensusEncoding;

/// Requests an `inv` message that provides block header hashes starting from a particular
/// point in the blockchain. It allows a peer which has been disconnected or started for the
/// first time to get the data it needs to request the blocks it hasn't seen.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, ConsensusEncoding)]
pub struct GetBlocks {
    /// The protocol version number, same as in the version message.
    version: u32,
    /// One or more block header hashes (32 bytes each) in internal byte order. Must be provided
    /// in reverse order of block height. Highest height hashes first.
    block_header_hashes: Vec<BlockHash>,
    /// The last block header hash being requested. If none, hash is set to all zeroes which
    /// will send a maximum of 500 hashes.
    stop_hash: BlockHash,
}

impl GetBlocks {
    pub fn new(
        version: u32,
        block_header_hashes: Vec<BlockHash>,
        stop_hash: Option<BlockHash>,
    ) -> Self {
        Self {
            version,
            block_header_hashes,
            stop_hash: stop_hash.unwrap_or_else(BlockHash::all_zeros),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{Decodable, Encodable};
    use crate::util::test_util::hex_to_hash;

    #[test]
    pub fn test_getblocks_encode() -> Result<(), Box<dyn std::error::Error>> {
        let hex_data = hex::decode(
            "71110100\
            02\
            d39f608a7775b537729884d4e6633bb2\
            105e55a16a14d31b0000000000000000\
            5c3e6403d40837110a2e8afb602b1c01\
            714bda7ce23bea0a0000000000000000\
            00000000000000000000000000000000\
            00000000000000000000000000000000",
        )?;

        let hash1: BlockHash =
            hex_to_hash("d39f608a7775b537729884d4e6633bb2105e55a16a14d31b0000000000000000")?;
        let hash2: BlockHash =
            hex_to_hash("5c3e6403d40837110a2e8afb602b1c01714bda7ce23bea0a0000000000000000")?;

        let get_block_message = GetBlocks::new(70001, vec![hash1, hash2], None);
        let mut encoded = Vec::new();
        let _bytes_written = get_block_message.consensus_encode(&mut encoded)?;

        assert_eq!(hex_data, encoded);

        Ok(())
    }

    #[test]
    pub fn test_getblocks_decode() -> Result<(), Box<dyn std::error::Error>> {
        let hex_data = hex::decode(
            "71110100\
            02\
            d39f608a7775b537729884d4e6633bb2\
            105e55a16a14d31b0000000000000000\
            5c3e6403d40837110a2e8afb602b1c01\
            714bda7ce23bea0a0000000000000000\
            00000000000000000000000000000000\
            00000000000000000000000000000000",
        )?;

        let mut cursor = std::io::Cursor::new(&hex_data);
        let decoded_message = GetBlocks::consensus_decode(&mut cursor)?;

        let expected_version = 70001;
        let expected_hash1: BlockHash =
            hex_to_hash("d39f608a7775b537729884d4e6633bb2105e55a16a14d31b0000000000000000")?;
        let expected_hash2: BlockHash =
            hex_to_hash("5c3e6403d40837110a2e8afb602b1c01714bda7ce23bea0a0000000000000000")?;
        let expected_stop_hash = BlockHash::all_zeros();

        assert_eq!(decoded_message.version, expected_version);
        assert_eq!(decoded_message.block_header_hashes.len(), 2);
        assert_eq!(
            *decoded_message
                .block_header_hashes
                .first()
                .ok_or("Getting hash1")?,
            expected_hash1
        );
        assert_eq!(
            *decoded_message
                .block_header_hashes
                .get(1)
                .ok_or("Getting hash2")?,
            expected_hash2
        );
        assert_eq!(decoded_message.stop_hash, expected_stop_hash);

        Ok(())
    }
}
