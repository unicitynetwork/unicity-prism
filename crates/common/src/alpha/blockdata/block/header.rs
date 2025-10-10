//! Block header implementations.
//!
//! This module provides implementations of block headers for different
//! blockchain types. Currently supported:
//! - Bitcoin-compatible headers (wrapping Bitcoin's standard header)
//! - RandomX headers (for RandomX-based proof of work)

pub mod bitcoin;
pub mod randomx;

use ::bitcoin::BlockHash;
pub use bitcoin::BitcoinHeader;
pub use randomx::RandomXHeader;

use crate::alpha::{
    blockdata::block::ValidationError,
    consensus::{Decodable, Encodable},
    pow::Target,
};

/// Common trait for block headers.
///
/// This trait defines the interface that all block header implementations must
/// follow. It provides methods for accessing common header fields and
/// validating proof of work.
pub trait Header:
    Copy + Clone + PartialEq + Eq + std::fmt::Debug + Send + Sync + Encodable + Decodable
{
    /// The size of the header in bytes.
    const SIZE: usize;

    /// Retrieves the previous block hash from the header.
    ///
    /// # Returns
    ///
    /// * BlockHash - The hash of the previous block
    fn previous_block_hash(&self) -> BlockHash;

    /// Computes the block hash.
    ///
    /// # Returns
    ///
    /// The block hash as a 256-bit hash value
    fn block_hash(&self) -> BlockHash;

    /// Extracts the difficulty target from the header.
    ///
    /// # Returns
    ///
    /// * `Some(Target)` - The converted target value
    /// * `None` - If the header doesn't have a valid target
    fn target(&self) -> Option<Target>;

    fn timestamp(&self) -> u32;

    /// Validates the proof of work against the required target.
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
    fn validate_pow(&self, required_target: Target) -> Result<BlockHash, ValidationError>;
}
