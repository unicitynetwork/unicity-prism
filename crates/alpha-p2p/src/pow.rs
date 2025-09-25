use alpha_p2p_derive::ConsensusCodec;
use primitive_types::U256;
use serde::{Deserialize, Serialize};

/// Represents the target threshold a block's hash must be below for the block to be
/// considered valid in Proof of Work consensus.
///
/// The target is a 256-bit unsigned integer, where lower values represent
/// higher difficulty. The maximum target (the easiest difficulty) is typically
/// defined by the network's genesis block.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Target(U256);

impl Target {
    /// Creates a new Target from a U256.
    pub fn new(target: U256) -> Self {
        Target(target)
    }

    /// Computes the difficulty for mining.
    /// `max_attainable_target` is the highest (easiest) target possible, usually
    /// the genesis target.
    /// Returns `u128::MAX` if the difficulty exceeds `u128::MAX`.
    pub fn difficulty(self, max_attainable_target: Target) -> u128 {
        let diff = max_attainable_target.0 / self.0;
        if diff > U256::from(u128::MAX) {
            u128::MAX
        } else {
            diff.as_u128()
        }
    }

    /// Computes the compact representation of the target, as used in block headers.
    ///
    /// Reference: <https://developer.bitcoin.org/reference/block_chain.html#target-nbits>
    pub fn from_compact(compact: CompactTarget) -> Self {
        let n = compact.0;
        let exponent = n >> 24;
        let mantissa = n & 0x007fffff;
        let target = if exponent <= 3 {
            U256::from(mantissa) >> (8 * (3 - exponent))
        } else {
            U256::from(mantissa) << (8 * (exponent - 3))
        };
        Target(target)
    }

    /// Converts the Target to its compact representation.
    pub fn to_compact(self) -> CompactTarget {
        let mut size = ((self.0.bits() + 7) / 8) as u32; // Number of bytes needed
        if size == 0 {
            return CompactTarget(0);
        }
        let mut compact: u32;
        if size <= 3 {
            compact = (self.0.low_u32() & 0xffffff) << (8 * (3 - size));
        } else {
            let shifted = self.0 >> (8 * (size - 3));
            compact = shifted.low_u32() & 0xffffff;
        }
        // If the mantissa's highest bit is set, we need to shift it down and increase the exponent
        if compact & 0x00800000 != 0 {
            compact >>= 8;
            size += 1;
        }
        compact |= size << 24;
        CompactTarget(compact)
    }
}

/// Compact representation of a Target, as used in block headers.
#[derive(
    Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ConsensusCodec,
)]
pub struct CompactTarget(u32);

impl CompactTarget {
    pub fn new(target: u32) -> Self {
        CompactTarget(target)
    }
}
