use crate::blockdata::block::BlockHash;
use crate::hashes::Hash;
use alpha_p2p_derive::ConsensusCodec;

/// Requests an `headers` message that provides block header hashes starting from a particular
/// point in the blockchain. It allows a peer which has been disconnected or started for the
/// first time to get the data it needs to request the headers it hasn't seen.
///
/// This message is used to synchronize block header information between peers in the Bitcoin
/// network. The requesting peer sends a list of known block hashes (locators) and a stop hash,
/// and the responding peer returns headers for blocks starting from the first locator that is
/// found in the local chain. Up to a maximum of 2000 headers or until the stop hash is reached.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, ConsensusCodec)]
pub struct GetHeaders {
    /// The protocol version number, same as in the version message.
    version: u32,
    /// One or more block header hashes (32 bytes each) in internal byte order. Must be provided
    /// in reverse order of block height. Highest height hashes first.
    ///
    /// These are the locator hashes used to find the starting point in the chain
    /// where headers should be sent from.
    hashes: Vec<BlockHash>,
    /// The last block header hash being requested. If none, hash is set to all zeroes which
    /// will send a maximum of 2,000 headers.
    ///
    /// This is used to limit the response size. When set to all zeros, it indicates
    /// that headers should be sent up to the maximum allowed (2000 headers).
    stop_hash: BlockHash,
}

impl GetHeaders {
    /// The maximum number of headers that can be requested in a single `getheaders` message.
    /// This limit is imposed to prevent excessive resource usage and ensure efficient
    /// synchronization between peers.
    pub const MAX_HEADERS: usize = 2000;

    /// Creates a new `GetHeaders` message.
    ///
    /// # Arguments
    /// * `version` - The protocol version number, same as in the version message.
    /// * `hashes` - One or more block header hashes (32 bytes each) in internal byte order.
    ///   Must be provided in reverse order of block height. Highest height hashes first.
    /// * `stop_hash` - The last block header hash being requested. If None, the default
    ///   value (all zeros) is used, which will send a maximum of 2,000 headers.
    ///
    /// # Returns
    /// A new instance of `GetHeaders` message.
    pub fn new(version: u32, hashes: Vec<BlockHash>, stop_hash: Option<BlockHash>) -> Self {
        Self {
            version,
            hashes,
            stop_hash: stop_hash.unwrap_or_else(BlockHash::all_zeros),
        }
    }

    /// Gets the protocol version of this message.
    ///
    /// The version number is used to ensure compatibility between peers and is
    /// typically the same as in the version message.
    ///
    /// # Returns
    /// * `u32` - The protocol version number.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Gets the locator hashes of this message.
    ///
    /// These are the block header hashes used to find the starting point in the chain
    /// where headers should be sent from. The hashes are provided in reverse order of
    /// block height, with the highest height hashes first.
    ///
    /// # Returns
    /// * `&[BlockHash]` - A slice of block header hashes.
    pub fn hashes(&self) -> &[BlockHash] {
        &self.hashes
    }

    /// Gets the stop hash of this message.
    ///
    /// The stop hash indicates the last block header hash being requested. If set to all
    /// zeroes, it signals that headers should be sent up to the maximum allowed (2000 headers).
    ///
    /// # Returns
    /// * `&BlockHash` - A reference to the stop hash.
    pub fn stop_hash(&self) -> &BlockHash {
        &self.stop_hash
    }

    /// Clears all locator hashes from the request.
    ///
    /// This method is useful when reusing a `GetHeaders` message instance
    /// to avoid carrying over previous locator hashes.
    pub fn clear_hashes(&mut self) {
        self.hashes.clear();
    }

    /// Resets the stop hash to the default value (all zeros).
    ///
    /// This method is useful when reusing a `GetHeaders` message instance
    /// to ensure that the maximum response size (2000 headers) is used.
    pub fn clear_stop_hash(&mut self) {
        self.stop_hash = BlockHash::all_zeros();
    }

    /// Resets all fields of the message to their default values.
    ///
    /// This method clears locator hashes and resets the stop hash to
    /// the default value (all zeros).
    pub fn clear(&mut self) {
        self.clear_hashes();
        self.clear_stop_hash();
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

        let get_block_message = GetHeaders::new(70001, vec![hash1, hash2], None);
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
        let decoded_message = GetHeaders::consensus_decode(&mut cursor)?;

        let expected_version = 70001;
        let expected_hash1: BlockHash =
            hex_to_hash("d39f608a7775b537729884d4e6633bb2105e55a16a14d31b0000000000000000")?;
        let expected_hash2: BlockHash =
            hex_to_hash("5c3e6403d40837110a2e8afb602b1c01714bda7ce23bea0a0000000000000000")?;
        let expected_stop_hash = BlockHash::all_zeros();

        assert_eq!(decoded_message.version, expected_version);
        assert_eq!(decoded_message.hashes.len(), 2);
        assert_eq!(
            *decoded_message.hashes.first().ok_or("Getting hash1")?,
            expected_hash1
        );
        assert_eq!(
            *decoded_message.hashes.get(1).ok_or("Getting hash2")?,
            expected_hash2
        );
        assert_eq!(decoded_message.stop_hash, expected_stop_hash);

        Ok(())
    }
}
