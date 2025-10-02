//! Bitcoin-compatible block header implementation.
//!
//! This module provides a wrapper around Bitcoin's standard block header that implements
//! the common [`Header`] trait, enabling compatibility with existing Bitcoin infrastructure
//! while maintaining the interface required by the Unicity Alpha network.

use crate::blockdata::block::Header;
use crate::pow::Target;
use alpha_p2p_derive::ConsensusCodec;
use bitcoin::block::ValidationError;
pub use bitcoin::blockdata::block::Header as InnerBitcoinHeader;
use bitcoin::BlockHash;
use serde::{Deserialize, Serialize};

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
pub struct BitcoinHeader(InnerBitcoinHeader);

impl Header for BitcoinHeader {
    /// The size of a Bitcoin block header in bytes.
    ///
    /// Bitcoin headers are always 80 bytes, following the Bitcoin protocol specification.
    const SIZE: usize = InnerBitcoinHeader::SIZE;

    /// Computes the block hash using Bitcoin's standard double-SHA256 algorithm.
    ///
    /// This method delegates to the underlying Bitcoin header's block_hash method,
    /// which performs the standard Bitcoin hashing algorithm (double SHA-256) on the header.
    ///
    /// # Returns
    ///
    /// The block hash as a 256-bit hash value
    fn block_hash(&self) -> BlockHash {
        self.0.block_hash()
    }

    /// Extracts the difficulty target from the header.
    ///
    /// Bitcoin headers store the target in a compact format (32 bits). This method
    /// converts the compact target to a full 256-bit target value that can be used
    /// for difficulty calculations and proof-of-work validation.
    ///
    /// # Returns
    ///
    /// * `Some(Target)` - The converted target value
    /// * `None` - Never returns None for Bitcoin headers as they always have a valid target
    fn target(&self) -> Option<Target> {
        Some(Target::from_bytes(&self.0.target().to_be_bytes()))
    }

    /// Validates the proof of work against the required target.
    ///
    /// This method should verify that the block hash is below the required target,
    /// confirming that the miner has performed sufficient work to satisfy the difficulty.
    ///
    /// # Arguments
    ///
    /// * `required_target` - The target that the block hash must be below to be valid
    ///
    /// # Returns
    ///
    /// * `Ok(BlockHash)` - If the proof of work is valid, returns the block hash
    /// * `Err(ValidationError)` - If the proof of work is invalid
    fn validate_pow(&self, required_target: Target) -> Result<BlockHash, ValidationError> {
        self.0.validate_pow(required_target.into())
    }
}

impl From<InnerBitcoinHeader> for BitcoinHeader {
    /// Creates a new BitcoinHeader from a standard Bitcoin header.
    ///
    /// This conversion is straightforward as BitcoinHeader is just a thin wrapper
    /// around the standard Bitcoin header.
    ///
    /// # Arguments
    ///
    /// * `header` - The standard Bitcoin header to wrap
    ///
    /// # Returns
    ///
    /// A new BitcoinHeader instance wrapping the provided header
    fn from(header: InnerBitcoinHeader) -> Self {
        BitcoinHeader(header)
    }
}
