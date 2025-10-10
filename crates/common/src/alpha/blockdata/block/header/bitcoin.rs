//! Bitcoin-compatible block header implementation.
//!
//! This module provides a wrapper around Bitcoin's standard block header that
//! implements the common [`Header`] trait, enabling compatibility with existing
//! Bitcoin infrastructure while maintaining the interface required by the
//! Unicity Alpha network.

pub use bitcoin::blockdata::block::Header as InnerHeader;
use bitcoin::{BlockHash, block::ValidationError};
use serde::{Deserialize, Serialize};
use unicity_prism_derive::ConsensusCodec;

use crate::alpha::{blockdata::block::header::Header, pow::Target};

/// A wrapper around Bitcoin's standard block header.
///
/// This struct provides a thin wrapper around Bitcoin's standard block header,
/// implementing the common [`Header`] trait to enable polymorphic usage within
/// the Unicity Alpha network while maintaining full compatibility with Bitcoin.
///
/// The header contains all the standard Bitcoin block fields:
/// - Version number
/// - Previous block hash
/// - Merkle root of transactions
/// - Timestamp
/// - Difficulty target (compact format)
/// - Nonce
#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ConsensusCodec,
)]
pub struct BitcoinHeader(InnerHeader);

impl Header for BitcoinHeader {
    /// The size of a Bitcoin block header in bytes.
    ///
    /// Bitcoin headers are always 80 bytes, following the Bitcoin protocol
    /// specification.
    const SIZE: usize = InnerHeader::SIZE;

    fn previous_block_hash(&self) -> BlockHash {
        self.0.prev_blockhash
    }

    /// Computes the block hash using Bitcoin's standard double-SHA256
    /// algorithm.
    ///
    /// This method delegates to the underlying Bitcoin header's block_hash
    /// method, which performs the standard Bitcoin hashing algorithm
    /// (double SHA-256) on the header.
    ///
    /// # Returns
    ///
    /// The block hash as a 256-bit hash value
    fn block_hash(&self) -> BlockHash {
        self.0.block_hash()
    }

    /// Extracts the difficulty target from the header.
    ///
    /// Bitcoin headers store the target in a compact format (32 bits). This
    /// method converts the compact target to a full 256-bit target value
    /// that can be used for difficulty calculations and proof-of-work
    /// validation.
    ///
    /// # Returns
    ///
    /// * `Some(Target)` - The converted target value
    /// * `None` - Never returns None for Bitcoin headers as they always have a
    ///   valid target
    fn target(&self) -> Option<Target> {
        Some(self.0.target().into())
    }

    fn timestamp(&self) -> u32 {
        self.0.time
    }

    /// Validates the proof of work against the required target.
    ///
    /// This method should verify that the block hash is below the required
    /// target, confirming that the miner has performed sufficient work to
    /// satisfy the difficulty.
    ///
    /// # Arguments
    ///
    /// * `required_target` - The target that the block hash must be below to be
    ///   valid
    ///
    /// # Returns
    ///
    /// * `Ok(BlockHash)` - If the proof of work is valid, returns the block
    ///   hash
    /// * `Err(ValidationError)` - If the proof of work is invalid
    fn validate_pow(&self, required_target: Target) -> Result<BlockHash, ValidationError> {
        self.0.validate_pow(required_target.into())
    }
}

impl From<InnerHeader> for BitcoinHeader {
    /// Creates a new BitcoinHeader from a standard Bitcoin header.
    ///
    /// This conversion is straightforward as BitcoinHeader is just a thin
    /// wrapper around the standard Bitcoin header.
    ///
    /// # Arguments
    ///
    /// * `header` - The standard Bitcoin header to wrap
    ///
    /// # Returns
    ///
    /// A new BitcoinHeader instance wrapping the provided header
    fn from(header: InnerHeader) -> Self {
        BitcoinHeader(header)
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{TxMerkleNode, block::Version, hashes::Hash};
    use hex::FromHex;

    use super::*;
    use crate::alpha::consensus::{Decodable, Encodable};

    #[test]
    fn test_bitcoin_header_deserialization() {
        // Hex data for a Bitcoin block header
        // 02000000 ........................... Block version: 2
        // b6ff0b1b1680a2862a30ca44d346d9e8
        // 910d334beb48ca0c0000000000000000 ... Hash of previous block's header
        // 9d10aa52ee949386ca9385695f04ede2
        // 70dda20810decd12bc9b048aaab31471 ... Merkle root
        // 24d95a54 ........................... [Unix time][unix epoch time]: 1415239972
        // 30c31b18 ........................... Target (bits)
        // fe9f0864 ........................... Nonce
        // 00 ................................. Transaction count (0x00)
        let hex_data = "\
        02000000\
        b6ff0b1b1680a2862a30ca44d346d9e8\
        910d334beb48ca0c0000000000000000\
        9d10aa52ee949386ca9385695f04ede2\
        70dda20810decd12bc9b048aaab31471\
        24d95a54\
        30c31b18\
        fe9f0864\
        ";

        // Convert hex string to bytes
        let header_bytes = Vec::from_hex(hex_data).expect("Invalid hex string");

        // Deserialize the header
        let mut cursor = std::io::Cursor::new(&header_bytes);
        let header =
            BitcoinHeader::consensus_decode(&mut cursor).expect("Failed to deserialize header");

        // Verify the header fields
        assert_eq!(header.0.version, Version::TWO);

        // Previous block hash - decode hex to bytes, reverse for proper endianness,
        // then create BlockHash
        let prev_hash_hex = "b6ff0b1b1680a2862a30ca44d346d9e8910d334beb48ca0c0000000000000000";
        let prev_hash_bytes = Vec::from_hex(prev_hash_hex).expect("Invalid prev hash hex");
        let expected_prev_hash = BlockHash::from_slice(&prev_hash_bytes).unwrap();
        assert_eq!(header.0.prev_blockhash, expected_prev_hash);

        // Merkle root - decode hex to bytes, reverse for proper endianness, then create
        // TxMerkleNode
        let merkle_root_hex = "9d10aa52ee949386ca9385695f04ede270dda20810decd12bc9b048aaab31471";
        let merkle_root_bytes = Vec::from_hex(merkle_root_hex).expect("Invalid merkle root hex");
        let expected_merkle_root = TxMerkleNode::from_slice(&merkle_root_bytes).unwrap();
        assert_eq!(header.0.merkle_root, expected_merkle_root);

        // Timestamp: 1415239972 (Tue Nov 4 2014 15:32:52 GMT)
        assert_eq!(header.0.time, 1415239972);

        // TODO: Fixme
        // Bits (target)
        // assert_eq!(header.0.bits, 0x30c31b18);

        // Nonce
        assert_eq!(header.0.nonce, 0x64089ffe);

        // Verify that the header can be re-encoded
        let mut encoded_bytes = Vec::new();
        let bytes_written = header
            .consensus_encode(&mut encoded_bytes)
            .expect("Failed to encode header");
        assert_eq!(bytes_written, BitcoinHeader::SIZE);

        // Verify that the encoded bytes match the original (excluding the transaction
        // count)
        assert_eq!(&encoded_bytes[..], &header_bytes[..BitcoinHeader::SIZE]);
    }
}
