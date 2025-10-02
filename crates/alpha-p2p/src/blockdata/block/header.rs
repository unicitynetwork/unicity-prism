//! Block header implementations for the Unicity Alpha network.
//!
//! This module defines a common trait that all block header implementations must follow,
//! enabling polymorphic handling of different header types. Currently, there are two
//! implementations:
//! - [`BitcoinHeader`] - A wrapper around Bitcoin's standard block header
//! - [`RandomXHeader`] - A custom header implementation for RandomX-based blocks

use crate::blockdata::block::{BlockHash, ValidationError};
use crate::pow::{Target, Work};
use ::bitcoin::consensus::{Decodable, Encodable};

mod bitcoin;
mod randomx;

pub use bitcoin::BitcoinHeader;
pub use randomx::RandomXHeader;

/// A common trait that all block header implementations must implement.
///
/// This trait defines the interface for block headers in the Unicity Alpha network,
/// providing methods for hashing, target validation, and difficulty calculation.
/// All header types must be thread-safe and serializable for network transmission.
pub trait Header: Encodable + Decodable + Send + Sync {
    /// The exact size of the header in bytes.
    ///
    /// Each header implementation must specify its exact size to ensure
    /// proper serialization and deserialization.
    const SIZE: usize;

    /// Retrieves the hash of the current block.
    ///
    /// This function returns the cryptographic hash that uniquely identifies
    /// the current block in the blockchain. The block hash is calculated
    /// based on the block's contents including previous block hash, timestamp,
    /// transaction data, and other block metadata.
    ///
    /// # Returns
    ///
    /// * `BlockHash` - A cryptographic hash representing the unique identifier
    ///   of the current block
    fn block_hash(&self) -> BlockHash;

    /// Returns the difficulty target for this block.
    ///
    /// The target represents the threshold that the block hash must be below
    /// to be considered valid. Lower targets indicate higher difficulty.
    ///
    /// # Returns
    ///
    /// * `Some(Target)` - The difficulty target if available
    /// * `None` - If the target cannot be determined
    fn target(&self) -> Option<Target>;

    /// Validates whether the current block's proof of work meets the required target difficulty.
    ///
    /// This function checks if the block's hash satisfies the minimum difficulty requirement
    /// specified by the target. In proof-of-work systems, blocks must contain a hash that
    /// meets or exceeds a certain threshold to be considered valid.
    ///
    /// # Arguments
    ///
    /// * `required_target` - The minimum hash value (target) that this block's hash must meet or exceed
    ///
    /// # Returns
    ///
    /// * `Ok(BlockHash)` - If the block's hash meets the required target, returns the validated hash
    /// * `Err(ValidationError)` - If the block's hash does not meet the required target, returns an error
    ///
    /// # Errors
    ///
    /// * `ValidationError::BadProofOfWork` - When the block's proof of work is insufficient
    /// * `ValidationError::BadTarget` - When the provided target is invalid or out of acceptable range
    fn validate_pow(&self, required_target: Target) -> Result<BlockHash, ValidationError>;

    /// Calculates the difficulty of the current block based on its target and the maximum attainable target.
    ///
    /// The difficulty represents how hard it is to mine this block compared to the maximum difficulty
    /// that can theoretically be achieved. It's expressed as a ratio where higher values indicate
    /// greater difficulty.
    ///
    /// # Arguments
    ///
    /// * `max_attainable_target` - The maximum target value that can be achieved in the network,
    ///   typically representing the highest difficulty (lowest target) possible
    ///
    /// # Returns
    ///
    /// * `Some(u128)` - The difficulty as a numeric value if the calculation can be performed
    /// * `None` - If the calculation cannot be performed (e.g., if targets are invalid or overflow occurs)
    fn difficulty(&self, max_attainable_target: Target) -> Option<u128> {
        self.target()
            .and_then(|t| t.difficulty(max_attainable_target))
    }

    /// Calculates the difficulty of the current target as a floating-point value
    /// relative to the maximum attainable target.
    ///
    /// This method converts the difficulty calculation from integer-based values
    /// to a floating-point representation, making it easier to work with in
    /// contexts that require decimal precision.
    ///
    /// # Arguments
    ///
    /// * `max_attainable_target` - The maximum target value that can be achieved,
    ///   used as the reference point for calculating difficulty
    ///
    /// # Returns
    ///
    /// * `Some(f64)` - The difficulty as a floating-point number if the calculation
    ///   can be performed, or `None` if the calculation fails due to invalid
    ///   target values or overflow conditions
    fn difficulty_float(&self, max_attainable_target: Target) -> Option<f64> {
        self.target()
            .and_then(|t| t.difficulty_float(max_attainable_target))
    }

    /// Converts the target into work, representing the amount of computational effort required.
    ///
    /// Work is the inverse of difficulty - it represents the expected number of hash attempts
    /// required to find a valid block at the current difficulty level.
    ///
    /// # Returns
    ///
    /// * `Some(Work)` - The work value if the conversion is successful
    /// * `None` - If the conversion fails
    fn work(&self) -> Option<Work> {
        self.target().and_then(|t| t.to_work())
    }
}
