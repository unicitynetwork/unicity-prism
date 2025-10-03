use alpha_p2p_derive::ConsensusCodec;

use crate::{blockdata::block::BlockHash, hashes::Hash};

/// Requests an `headers` message that provides block header hashes starting
/// from a particular point in the blockchain. It allows a peer which has been
/// disconnected or started for the first time to get the data it needs to
/// request the headers it hasn't seen.
///
/// This message is used to synchronize block header information between peers
/// in the Bitcoin network. The requesting peer sends a list of known block
/// hashes (locators) and a stop hash, and the responding peer returns headers
/// for blocks starting from the first locator that is found in the local chain.
/// Up to a maximum of 2000 headers or until the stop hash is reached.
///
/// ## API Contract
///
/// The `GetHeaders` message must be encoded and decoded using the
/// [ConsensusCodec] trait, ensuring compatibility with the Bitcoin protocol.
/// The encoded format includes:
///
/// 1. `version` (4 bytes): Protocol version number.
/// 2. `hashes_count` (1-9 bytes, varint): Number of locator hashes.
/// 3. `hashes` (32 bytes each): Block header hashes in reverse height order.
/// 4. `stop_hash` (32 bytes): Last block header hash to request, or all zeros
///    for max headers.
///
/// ## Usage Example
///
/// ```ignore
/// use alpha_p2p::blockdata::block::BlockHash;
/// use alpha_p2p::p2p::message_blockdata::GetHeaders;
/// use alpha_p2p::hashes::Hash;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Create a new GetHeaders message with default stop hash
/// let locator_hashes: Vec<BlockHash> = vec![
///     BlockHash::from_hex("0000000000000000000000000000000000000000000000000000000000000001")?,
///     BlockHash::from_hex("0000000000000000000000000000000000000000000000000000000000000002")?,
/// ];
///
/// let get_headers = GetHeaders::new(
///     70015, // protocol version
///     locator_hashes,
///     None // use default stop hash (all zeros)
/// );
///
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, ConsensusCodec)]
pub struct GetHeaders {
    /// The protocol version number, same as in the version message.
    ///
    /// This ensures compatibility with the responding peer's protocol version,
    /// and must typically be set to the same value as used in the `version`
    /// message.
    version: u32,

    /// One or more block header hashes (32 bytes each) in internal byte order.
    /// Must be provided in reverse order of block height. Highest height
    /// hashes first.
    ///
    /// These are the locator hashes used to find the starting point in the
    /// chain where headers should be sent from. The first hash that matches
    /// an actual block header in the local chain determines the beginning
    /// of the returned headers.
    ///
    /// # Note on Ordering
    /// The hashes must be ordered from highest to lowest block height (reverse
    /// chronological order), as this allows the receiving peer to quickly
    /// locate its best known block and start providing headers from there.
    ///
    /// # Limitations
    /// - A maximum of 10,000 locator hashes may be included in the message as
    ///   per BIP-144, although only up to 2000 headers are returned, as per
    ///   BIP-97.
    hashes: Vec<BlockHash>,

    /// The last block header hash being requested. If none, hash is set to all
    /// zeroes which will send a maximum of 2,000 headers.
    ///
    /// This is used to limit the response size. When set to all zeros, it
    /// indicates that headers should be sent up to the maximum allowed
    /// (2000 headers).
    ///
    /// # Usage
    /// If you are requesting headers from the most recent known block, set this
    /// to all zeros. Otherwise, specify a particular stop hash (e.g., the
    /// hash of an expected final block).
    ///
    /// # Format
    /// The format is a full 32-byte [BlockHash] in internal byte order.
    stop_hash: BlockHash,
}

impl GetHeaders {
    /// The maximum number of headers that can be requested in a single
    /// `getheaders` message.
    ///
    /// This limit is imposed to prevent excessive resource usage and ensure
    /// efficient synchronization between peers, as per [BIP-97](https://github.com/bitcoin/bips/blob/master/bip-0097.mediawiki).
    pub const MAX_HEADERS: usize = 2000;

    /// Creates a new `GetHeaders` message with the specified version, locator
    /// hashes, and an optional stop hash.
    ///
    /// # Arguments
    /// * `version` - The protocol version number, same as in the version
    ///   message.
    /// * `hashes` - One or more block header hashes (32 bytes each) in internal
    ///   byte order. Must be provided in reverse order of block height. Highest
    ///   height hashes first.
    /// * `stop_hash` - An optional [BlockHash] to specify the last block header
    ///   hash being requested. If `None`, the default value (all zeros) is
    ///   used, which will send a maximum of 2000 headers.
    ///
    /// # Returns
    /// A new instance of `GetHeaders` message.
    ///
    /// # Usage Example
    /// ```ignore
    /// use alpha_p2p::blockdata::block::BlockHash;
    /// use alpha_p2p::p2p::message_blockdata::GetHeaders;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let locator_hashes: Vec<BlockHash> = vec![
    ///     BlockHash::from_hex("0000000000000000000000000000000000000000000000000000000000000001")?,
    /// ];
    ///
    /// let get_headers = GetHeaders::new(
    ///     70015,
    ///     locator_hashes,
    ///     Some(BlockHash::from_hex("0000000000000000000000000000000000000000000000000000000000000002")?),
    /// );
    ///
    /// # Ok(())
    /// # }
    /// ```
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
    ///
    /// # Example
    /// ```ignore
    /// use alpha_p2p::p2p::message_blockdata::GetHeaders;
    ///
    /// let get_headers = GetHeaders::new(
    ///     70015,
    ///     vec![],
    ///     None
    /// );
    ///
    /// assert_eq!(get_headers.version(), 70015);
    /// ```
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Gets the locator hashes of this message.
    ///
    /// These are the block header hashes used to find the starting point in the
    /// chain where headers should be sent from. The hashes are provided in
    /// reverse order of block height, with the highest height hashes first.
    ///
    /// # Returns
    /// * `&[BlockHash]` - A slice of block header hashes.
    ///
    /// # Example
    /// ```ignore
    /// use alpha_p2p::blockdata::block::BlockHash;
    /// use alpha_p2p::p2p::message_blockdata::GetHeaders;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let locator_hashes: Vec<BlockHash> = vec![
    ///     BlockHash::from_hex("0000000000000000000000000000000000000000000000000000000000000001")?,
    /// ];
    ///
    /// let get_headers = GetHeaders::new(
    ///     70015,
    ///     locator_hashes.clone(),
    ///     None
    /// );
    ///
    /// assert_eq!(get_headers.hashes(), locator_hashes.as_slice());
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn hashes(&self) -> &[BlockHash] {
        &self.hashes
    }

    /// Gets the stop hash of this message.
    ///
    /// The stop hash indicates the last block header hash being requested. If
    /// set to all zeroes, it signals that headers should be sent up to the
    /// maximum allowed (2000 headers).
    ///
    /// # Returns
    /// * `&BlockHash` - A reference to the stop hash.
    ///
    /// # Example
    /// ```ignore
    /// use alpha_p2p::blockdata::block::BlockHash;
    /// use alpha_p2p::p2p::message_blockdata::GetHeaders;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let get_headers = GetHeaders::new(
    ///     70015,
    ///     vec![],
    ///     None // defaults to all zeros
    /// );
    ///
    /// assert_eq!(get_headers.stop_hash(), &BlockHash::all_zeros());
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn stop_hash(&self) -> &BlockHash {
        &self.stop_hash
    }

    /// Clears all locator hashes from the request.
    ///
    /// This method is useful when reusing a `GetHeaders` message instance
    /// to avoid carrying over previous locator hashes.
    ///
    /// # Example
    /// ```ignore
    /// use alpha_p2p::blockdata::block::BlockHash;
    /// use alpha_p2p::p2p::message_blockdata::GetHeaders;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut get_headers = GetHeaders::new(
    ///     70015,
    ///     vec![],
    ///     None
    /// );
    ///
    /// // Add some hashes to the message
    /// get_headers.hashes.push(BlockHash::from_hex("0000000000000000000000000000000000000000000000000000000000000001")?);
    ///
    /// // Clear the hashes
    /// get_headers.clear_hashes();
    ///
    /// assert!(get_headers.hashes().is_empty());
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn clear_hashes(&mut self) {
        self.hashes.clear();
    }

    /// Resets the stop hash to the default value (all zeros).
    ///
    /// This method is useful when reusing a `GetHeaders` message instance
    /// to ensure that the maximum response size (2000 headers) is used.
    ///
    /// # Example
    /// ```ignore
    /// use alpha_p2p::blockdata::block::BlockHash;
    /// use alpha_p2p::p2p::message_blockdata::GetHeaders;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut get_headers = GetHeaders::new(
    ///     70015,
    ///     vec![],
    ///     Some(BlockHash::from_hex("0000000000000000000000000000000000000000000000000000000000000001")?)
    /// );
    ///
    /// // Reset the stop hash to default
    /// get_headers.clear_stop_hash();
    ///
    /// assert_eq!(get_headers.stop_hash(), &BlockHash::all_zeros());
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn clear_stop_hash(&mut self) {
        self.stop_hash = BlockHash::all_zeros();
    }

    /// Resets all fields of the message to their default values.
    ///
    /// This method clears locator hashes and resets the stop hash to
    /// the default value (all zeros).
    ///
    /// # Example
    /// ```ignore
    /// use alpha_p2p::blockdata::block::BlockHash;
    /// use alpha_p2p::p2p::message_blockdata::GetHeaders;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut get_headers = GetHeaders::new(
    ///     70015,
    ///     vec![BlockHash::from_hex("0000000000000000000000000000000000000000000000000000000000000001")?],
    ///     Some(BlockHash::from_hex("0000000000000000000000000000000000000000000000000000000000000002")?)
    /// );
    ///
    /// // Reset all fields
    /// get_headers.clear();
    ///
    /// assert!(get_headers.hashes().is_empty());
    /// assert_eq!(get_headers.stop_hash(), &BlockHash::all_zeros());
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn clear(&mut self) {
        self.clear_hashes();
        self.clear_stop_hash();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::{Decodable, Encodable},
        util::hex_to_blockhash,
    };

    #[test]
    pub fn test_getheaders_encode() -> Result<(), Box<dyn std::error::Error>> {
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
            hex_to_blockhash("d39f608a7775b537729884d4e6633bb2105e55a16a14d31b0000000000000000")?;
        let hash2: BlockHash =
            hex_to_blockhash("5c3e6403d40837110a2e8afb602b1c01714bda7ce23bea0a0000000000000000")?;
        let get_headers_message = GetHeaders::new(70001, vec![hash1, hash2], None);
        let mut encoded = Vec::new();
        let _bytes_written = get_headers_message.consensus_encode(&mut encoded)?;
        assert_eq!(hex_data, encoded);
        Ok(())
    }

    #[test]
    pub fn test_getheaders_decode() -> Result<(), Box<dyn std::error::Error>> {
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
            hex_to_blockhash("d39f608a7775b537729884d4e6633bb2105e55a16a14d31b0000000000000000")?;
        let expected_hash2: BlockHash =
            hex_to_blockhash("5c3e6403d40837110a2e8afb602b1c01714bda7ce23bea0a0000000000000000")?;
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
