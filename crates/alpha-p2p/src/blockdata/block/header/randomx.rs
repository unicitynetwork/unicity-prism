//! RandomX block header implementation.
//!
//! This module provides a custom block header implementation for blocks using the RandomX
//! proof-of-work algorithm. RandomX is a proof-of-work algorithm that is optimized for
//! general-purpose CPUs and is designed to be ASIC-resistant.

use crate::blockdata::block::Header;
use crate::hashes::Hash;
use crate::pow::{CompactTarget, Target};
use alpha_p2p_derive::ConsensusCodec;
use bitcoin::block::ValidationError;
pub use bitcoin::block::{BlockHash, TxMerkleNode, Version};
use bitcoin::consensus::Encodable;
use serde::{Deserialize, Serialize};

/// Alpha block header for RandomX-based blocks.
///
/// This header contains all standard Bitcoin block fields plus an additional
/// RandomX hash field. It's designed for blocks that use the RandomX proof-of-work
/// algorithm, which is optimized for CPU mining and resistant to ASICs.
///
/// The header includes:
/// - Standard Bitcoin fields (version, previous hash, merkle root, timestamp, bits, nonce)
/// - Additional RandomX hash field for the RandomX proof-of-work
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ConsensusCodec,
)]
pub struct RandomXHeader {
    /// Block version, now repurposed for soft fork signaling.
    ///
    /// In Bitcoin, this field originally indicated block version rules,
    /// but is now used for signaling soft fork activation.
    pub version: Version,
    
    /// Reference to the previous block in the chain.
    ///
    /// This creates the cryptographic link between blocks, forming the blockchain.
    /// Each block must reference the hash of the previous block to be valid.
    pub previous_header: BlockHash,
    
    /// The root hash of the merkle tree of transactions in the block.
    ///
    /// This commits to all transactions in the block in a compact way,
    /// allowing for efficient verification of transaction inclusion.
    pub merkle_root: TxMerkleNode,
    
    /// The timestamp of the block, as claimed by the miner.
    ///
    /// This is a Unix timestamp indicating when the block was created.
    /// It's used in difficulty adjustment and has some constraints on valid values.
    pub timestamp: u32,
    
    /// The target value below which the blockhash must lie.
    ///
    /// This is the compact representation of the difficulty target.
    /// Miners must find a nonce that produces a block hash below this target.
    pub bits: CompactTarget,
    
    /// The nonce, selected to obtain a low enough blockhash.
    ///
    /// Miners increment this value to try different hashes until they find
    /// one that meets the difficulty target. This is the field they modify
    /// during mining.
    pub nonce: u32,
    
    /// The RandomX hash for this block.
    ///
    /// This additional field contains the RandomX proof-of-work hash,
    /// which is computed using the RandomX algorithm on the block header.
    /// RandomX is designed to be CPU-friendly and ASIC-resistant.
    pub randomx_hash: [u8; 32],
}

impl Header for RandomXHeader {
    /// The size of a RandomX block header in bytes.
    ///
    /// RandomX headers are 112 bytes, which is 32 bytes larger than standard
    /// Bitcoin headers due to the additional randomx_hash field.
    const SIZE: usize = 4 + 32 + 32 + 4 + 4 + 4 + 32; // 112

    /// Computes the block hash using Bitcoin's double-SHA256 algorithm.
    ///
    /// This method serializes the entire header (including the RandomX hash)
    /// and computes the double-SHA256 hash of the serialized data. This is
    /// different from the RandomX hash itself, which is computed using the
    /// RandomX algorithm.
    ///
    /// # Returns
    ///
    /// The block hash as a 256-bit hash value
    fn block_hash(&self) -> BlockHash {
        let mut engine = BlockHash::engine();
        #[allow(clippy::expect_used, reason = "Expected inputs can't fail")]
        self.consensus_encode(&mut engine)
            .expect("Expected inputs can't fail");
        BlockHash::from_engine(engine)
    }

    /// Extracts the difficulty target from the header.
    ///
    /// This method converts the compact target (bits) to a full 256-bit target
    /// value that can be used for difficulty calculations and proof-of-work validation.
    ///
    /// # Returns
    ///
    /// * `Some(Target)` - The converted target value if conversion succeeds
    /// * `None` - If the compact target is invalid
    fn target(&self) -> Option<Target> {
        Target::from_compact(self.bits)
    }

    /// Validates the proof of work against the required target.
    ///
    /// This method should verify that the RandomX hash is below the required target,
    /// confirming that the miner has performed sufficient RandomX work to satisfy the difficulty.
    ///
    /// # Arguments
    ///
    /// * `_required_target` - The target that the RandomX hash must be below to be valid
    ///
    /// # Returns
    ///
    /// * `Ok(BlockHash)` - If the proof of work is valid, returns the block hash
    /// * `Err(ValidationError)` - If the proof of work is invalid
    ///
    /// # TODO
    ///
    /// This method is currently unimplemented and needs to be completed.
    /// It should validate the RandomX hash against the target, not the block hash.
    fn validate_pow(&self, _required_target: Target) -> Result<BlockHash, ValidationError> {
        todo!()
    }
}
