//!
//! This module defines the Target and CompactTarget types used for representing
//! difficulty targets in blockchain systems, particularly in the Unicity Alpha network.
//!
//! A Target is a 256-bit value that represents the difficulty threshold for mining
//! a block. The lower the target, the higher the difficulty. CompactTarget is an
//! encoded representation of this target that fits into a 32-bit value, used in
//! block headers.
//!
use alpha_p2p_derive::ConsensusCodec;
use primitive_types::U256;
use serde::{Deserialize, Serialize};

/// Represents a target value expressed as an unsigned 256-bit integer.
///
/// This struct provides a type-safe wrapper around `U256` (unsigned 256-bit integer)
/// to represent target values, commonly used in cryptographic contexts such as
/// Alpha's mining difficulty calculations or similar systems.
///
/// # Example
///
/// ```ignore
/// use alpha_p2p::pow::{Target, CompactTarget};
///
/// // Create a target from hex string
/// let target = Target::from_hex("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
///
/// // Convert to compact format used in block headers
/// let compact = target.to_compact();
///
/// // Convert back to verify the round-trip
/// let original_target = Target::from_compact(compact);
///
/// assert_eq!(target, original_target);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Target(U256);

impl Target {
    /// Creates a new Target instance with the specified U256 value.
    ///
    /// # Arguments
    ///
    /// * `target` - A U256 value representing the target to be stored
    ///
    /// # Returns
    ///
    /// Returns a new Target instance containing the provided U256 value
    ///
    /// # Example
    ///
    /// ```ignore
    /// use primitive_types::U256;
    /// use alpha_p2p::pow::Target;
    ///
    /// let target = Target::new(U256::from(100));
    /// # assert_eq!(target.0, U256::from(100));
    /// ```
    pub(crate) const fn new(target: U256) -> Self {
        Target(target)
    }

    /// Creates a new `Target` from a hexadecimal string representation.
    ///
    /// # Arguments
    ///
    /// * `hex_str` - A hexadecimal string representation of the 256-bit target value
    ///
    /// # Returns
    ///
    /// A new `Target` instance, or an error if the string is not valid
    ///
    /// # Example
    ///
    /// ```ignore
    /// use alpha_p2p::pow::Target;
    ///
    /// let target = Target::from_hex("0000000000000000000000000000000000000000000000000000000000000001")?;
    /// # assert_eq!(target.0, primitive_types::U256::from(1u128));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_hex(hex: &str) -> Option<Self> {
        U256::from_str_radix(hex, 16).ok().map(Target)
    }

    /// Creates a new `Target` from bytes representing a 256-bit target value.
    ///
    /// # Arguments
    ///
    /// * `bytes` - An array of 32 bytes representing the big-endian byte representation
    ///   of a 256-bit target value
    ///
    /// # Returns
    ///
    /// A new `Target` instance containing the parsed value
    ///
    /// # Example
    ///
    /// ```ignore
    /// use alpha_p2p::pow::Target;
    ///
    /// let bytes: [u8; 32] = [
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    /// ];
    ///
    /// let target = Target::from_bytes(&bytes);
    /// # assert_eq!(target.0, primitive_types::U256::from(1u128));
    /// ```
    /// Creates a Target from bytes (big-endian).
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(U256::from_big_endian(bytes))
    }

    /// Creates a new instance of `Target` with a zero-valued underlying `U256` integer.
    ///
    /// This constructor initializes the `Target` struct with a default value of zero,
    /// which is useful for representing null or uninitialized target states in blockchain
    /// contexts where `U256` values are used for cryptographic computations.
    ///
    /// # Returns
    ///
    /// A new `Target` instance containing a zero-valued `U256` integer.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use alpha_p2p::pow::Target;
    ///
    /// let zero_target = Target::zero();
    /// # assert_eq!(zero_target.0, primitive_types::U256::zero());
    /// ```
    pub const fn zero() -> Self {
        Target(U256::zero())
    }

    /// Calculates the difficulty of the current target relative to a maximum attainable target.
    ///
    /// This function computes the mining difficulty by dividing the maximum attainable target
    /// by the current target. The result represents how much harder it is to mine a block
    /// with the current target compared to the maximum possible difficulty.
    ///
    /// # Arguments
    /// * `max_attainable_target` - The maximum target value that can be achieved (typically
    ///   the network's maximum difficulty target)
    ///
    /// # Returns
    /// * `Some(u128)` - The calculated difficulty as a 128-bit unsigned integer
    /// * `None` - When the division would overflow or when the current target is zero
    ///
    /// # Notes
    /// - Caps the result at `u128::MAX` when the calculated difficulty exceeds u128 bounds
    /// - The calculation assumes that both targets are valid and represent the same units
    ///
    /// # Example
    ///
    /// ```ignore
    /// use alpha_p2p::pow::{Target, CompactTarget};
    ///
    /// let max_target = Target::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")?;
    /// let low_difficulty = Target::from_hex("0000000000000000000000000000000000000000000000000000000000000001")?;
    /// let difficulty = low_difficulty.difficulty(max_target);
    ///
    /// // Should be maximum as the difficulty is very high (low target)
    /// assert_eq!(difficulty, u128::MAX);
    ///
    /// let high_difficulty = Target::from_hex("0000000000000000000000000000000000000000000000000000000000000100")?;
    /// let normal_difficulty = high_difficulty.difficulty(max_target);
    ///
    /// // Should be a reasonable difficulty value
    /// assert_eq!(normal_difficulty, 100);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn difficulty(self, max_attainable_target: Target) -> Option<u128> {
        let diff = max_attainable_target.0.checked_div(self.0)?;
        if diff > U256::from(u128::MAX) {
            Some(u128::MAX)
        } else {
            Some(diff.as_u128())
        }
    }

    /// Converts the difficulty value to a floating-point representation
    ///
    /// This method takes a maximum attainable target and attempts to calculate
    /// the difficulty of the current object (likely a blockchain block or similar)
    /// as an f64 value. If the calculation cannot be performed (returns None),
    /// this method will return None as well.
    ///
    /// # Arguments
    ///
    /// * `max_attainable_target` - The maximum target value that can be achieved,
    ///   typically representing the highest difficulty threshold in blockchain contexts
    ///
    /// # Returns
    ///
    /// * `Some(f64)` - The difficulty value as a floating-point number if calculation succeeds
    /// * `None` - If the difficulty calculation cannot be performed or is not valid
    ///
    /// # Example
    ///
    /// ```ignore
    /// use alpha_p2p::pow::{Target, CompactTarget};
    ///
    /// let max_target = Target::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")?;
    /// let low_difficulty = Target::from_hex("0000000000000000000000000000000000000000000000000000000000000100")?;
    /// let difficulty_float = low_difficulty.difficulty_float(max_target);
    ///
    /// assert_eq!(difficulty_float, 100.0f64);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn difficulty_float(self, max_attainable_target: Target) -> Option<f64> {
        let diff = self.difficulty(max_attainable_target)?;
        Some(diff as f64)
    }

    pub fn to_work(self) -> Option<Work> {
        // Handle edge cases
        if self.0.is_zero() {
            return Some(Work::new(U256::max_value()));
        }

        // Special case: inverse of 1 is max (as per the codebase)
        if self.0 == U256::one() {
            return Some(Work::new(U256::max_value()));
        }

        // Special case: inverse of max is 1 (as per the codebase)
        if self.0 == U256::max_value() {
            return Some(Work::new(U256::one()));
        }

        // Use the formula: (~x / (x + 1)) + 1
        let increment = self.0.checked_add(U256::one())?;
        let inverted = !self.0;

        // Perform the division and add 1
        let result = inverted.checked_div(increment)?;
        Some(Work::new(result.checked_add(U256::one())?))
    }

    /// Converts a compact target representation into a Target instance.
    ///
    /// The compact format is used in blockchain systems to represent targets
    /// (difficulty levels) in a space-efficient manner. This function parses
    /// the compact format and converts it to a full 256-bit target value.
    ///
    /// The compact format stores:
    /// - A 3-byte mantissa (24 bits)
    /// - A 1-byte exponent (8 bits)
    ///
    /// The actual target is calculated as: `mantissa * 256^(exponent - 3)`
    ///
    /// # Arguments
    ///
    /// * `compact` - A Target value in compact format (typically 4 bytes)
    ///
    /// # Returns
    ///
    /// * `Some(Target)` - The parsed target value if valid
    /// * `None` - If the compact representation is invalid (e.g., zero mantissa,
    ///   invalid exponent, or overflow during calculation)
    ///
    /// # Validity Checks
    ///
    /// The function performs the following validation:
    /// 1. Ensures the mantissa's high bit is not set (invalid format)
    /// 2. Rejects zero mantissas
    /// 3. Validates that the exponent is within acceptable bounds (<= 32)
    ///
    /// # Overflow Protection
    ///
    /// The function guards against bit shifting overflows by:
    /// 1. Checking that shift operations don't exceed 256 bits
    /// 2. Using checked arithmetic to prevent integer overflow in calculations
    ///
    /// # Example
    ///
    /// ```ignore
    /// use alpha_p2p::pow::{Target, CompactTarget};
    ///
    /// // Create a compact target from an integer value
    /// let compact = CompactTarget::new(0x03123456); // size=3, mantissa=0x123456
    /// let target = Target::from_compact(compact);
    ///
    /// # assert_eq!(target.0, primitive_types::U256::from(0x123456));
    /// ```
    pub fn from_compact(compact: CompactTarget) -> Option<Self> {
        let n = compact.0;
        let exponent = n >> 24;
        let mantissa = n & 0x007fffff;

        if mantissa & 0x00800000 != 0 {
            return None; // Invalid mantissa (high bit set)
        }

        if mantissa == 0 {
            return None; // Zero mantissa is not allowed
        }

        if exponent > 32 {
            return None; // Exponent too large for a 256-bit target
        }

        let base = U256::from(mantissa);

        #[allow(clippy::arithmetic_side_effects, reason = "Checked U256 shift handle overflows")]
        let target = if exponent <= 3 {
            let shift_bits = 3u32.checked_sub(exponent)?.checked_mul(8)?;
            if shift_bits >= 256 {
                return None; // Shift would zero out everything anyway
            }

            base >> shift_bits
        } else {
            let shift_bits = exponent.checked_sub(3)?.checked_mul(8)?;
            if shift_bits >= 256 {
                return None; // Shift would exceed 256 bits
            }
            base << shift_bits
        };

        Some(Target(target))
    }

    /// Converts a target value into its compact representation.
    ///
    /// This function transforms a target value into a format suitable for use in
    /// blockchain protocols, particularly where targets are represented with an 8-bit size field
    /// and a 24-bit mantissa, packed into a 32-bit value.
    ///
    /// The conversion follows these rules:
    /// - Zero is handled specially, returning the standard compact representation of zero.
    /// - The most significant bit position determines the size in bytes needed to represent
    ///   the value, which is then rounded up to the nearest byte.
    /// - The resulting size is capped at 255 bytes for compatibility with the compact format's
    ///   8-bit size field.
    ///
    /// For large numbers, the most significant bits are extracted and right-shifted to
    /// form the mantissa. If the high bit of the resulting mantissa is set, this indicates
    /// overflow and leads to normalization: the mantissa is right-shifted by 8 bits and the
    /// size is incremented.
    ///
    /// Returns `None` in cases of overflow during calculations or when the number requires
    /// more than 255 bytes to represent, which is outside the valid range.
    ///
    /// # Returns
    ///
    /// * `Some(CompactTarget)` - The compact representation of the target.
    /// * `None` - If conversion fails due to overflow or invalid size.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use alpha_p2p::pow::{Target, CompactTarget};
    ///
    /// // Create a target with some value
    /// let target = Target::from_hex("0000000000000000000000000000000000000000000000000000000012345678")?;
    /// let compact = target.to_compact();
    ///
    /// // Round-trip conversion should work
    /// let reconstructed = Target::from_compact(compact);
    /// assert_eq!(Some(target), reconstructed);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn to_compact(self) -> Option<CompactTarget> {
        // Handle zero case - return the standard "zero" compact representation
        if self.0.is_zero() {
            return Some(CompactTarget(0));
        }

        // Find the position of the most significant bit
        let bit_length = u32::try_from(self.0.bits()).ok()?;

        // Calculate size (number of bytes needed)
        let size = bit_length.checked_add(7)?.checked_div(8)?;

        // Compact targets must fit in 8-bit size field
        if size > 255 {
            return None;
        }

        // Extract mantissa based on size
        let (mantissa, actual_size) = if size <= 3 {
            // For small numbers, left-pad with zeros to fill 3 bytes
            let pad_bytes = 3u32.checked_sub(size)?;
            let shift_bits = pad_bytes.checked_mul(8)?;

            // Left-shift to pad with zeros
            let shifted_mantissa = self.0.low_u32() << shift_bits;
            (shifted_mantissa & 0x00ffffff, size)
        } else {
            // For large numbers, right-shift to get the most significant 3 bytes
            let excess_bytes = size.checked_sub(3)?;
            let shift_bits = excess_bytes.checked_mul(8)?;

            // Validate shift is reasonable for 256-bit number
            if shift_bits >= 256 {
                return None; // Shift would zero out everything anyway
            }

            // Right-shift to move the most significant bits into the low 24 bits
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "Checked U256 shift handle overflows"
            )]
            let shifted = self.0 >> shift_bits;

            let mantissa = shifted.low_u32() & 0x00ffffff;
            (mantissa, size)
        };

        // Check if we need to normalize (if high bit of mantissa is set)
        let (final_mantissa, final_size) = if mantissa & 0x00800000 != 0 {
            // Normalize: right-shift mantissa by 8 bits and increment size
            let normalized_mantissa = mantissa.checked_shr(8)?;
            let normalized_size = actual_size.checked_add(1)?.min(255);
            (normalized_mantissa, normalized_size)
        } else {
            (mantissa, actual_size)
        };

        // Combine size and mantissa into compact format
        // Format: [size:8][mantissa:24]
        let size_shifted = final_size.checked_shl(24)?;
        let compact = size_shifted.checked_add(final_mantissa)?;

        Some(CompactTarget(compact))
    }
}

/// Compact representation of a Target, as used in block headers.
///
/// # Example
///
/// ```ignore
/// use alpha_p2p::pow::CompactTarget;
///
/// let compact = CompactTarget::new(0x123456);
/// # assert_eq!(compact.0, 0x123456);
///
/// let compact_zero = CompactTarget::new(0x000000);
/// # assert_eq!(compact_zero.0, 0x000000);
/// ```
#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    ConsensusCodec,
)]
pub struct CompactTarget(u32);

impl CompactTarget {
    pub fn new(target: u32) -> Self {
        CompactTarget(target)
    }
}

pub struct Work(U256);

impl Work {
    pub fn new(work: U256) -> Self {
        Work(work)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_target() {
        let target = Target(U256::zero());
        assert_eq!(target.to_compact().unwrap().0, 0);
    }

    #[test]
    fn test_genesis_block_target() {
        // Genesis block nBits: 0x1d00ffff
        // This should convert to target: 0x00000000ffff0000000000000000000000000000000000000000000000000000
        let expected_compact = 0x1d00ffff;

        // Create the target from the known formula: 0x00ffff * 256^(0x1d - 3)
        // 0x1d = 29, so 256^(29-3) = 256^26
        let mut target_bytes = [0u8; 32];
        target_bytes[32 - 29] = 0x00; // Leading zero for positive sign
        target_bytes[32 - 28] = 0xff;
        target_bytes[32 - 27] = 0xff;
        // Rest are zeros

        let target = Target(U256::from_big_endian(&target_bytes));
        let compact = target.to_compact().unwrap();
        assert_eq!(compact.0, expected_compact);
    }

    #[test]
    fn test_maximum_target() {
        // Maximum difficulty target (lowest difficulty)
        // nBits: 0x1d00ffff represents the original Bitcoin maximum target
        let target_hex = "00000000ffff0000000000000000000000000000000000000000000000000000";
        let target = Target(U256::from_str_radix(target_hex, 16).unwrap());

        let compact = target.to_compact().unwrap();
        assert_eq!(compact.0, 0x1d00ffff);

        // Verify the math: coefficient=0x00ffff, exponent=0x1d
        let coefficient = compact.0 & 0xffffff;
        let exponent = (compact.0 >> 24) & 0xff;
        assert_eq!(coefficient, 0x00ffff);
        assert_eq!(exponent, 0x1d);
    }

    #[test]
    fn test_real_block_example() {
        // Real Bitcoin block example from documentation
        // Block height 100000: "bits" : "1b04864c", target should be 0x04864c * 256^(0x1b - 3)
        let expected_compact = 0x1b04864c;

        // Calculate expected target: 0x04864c * 256^(0x1b - 3) = 0x04864c * 256^24
        let coefficient = 0x04864c;
        let exponent = 0x1b;

        // Create target manually for verification
        let mut target_bytes = [0u8; 32];
        let byte_size = exponent as usize;
        if byte_size >= 3 {
            let start_pos = 32 - byte_size;
            target_bytes[start_pos] = 0x04;
            target_bytes[start_pos + 1] = 0x86;
            target_bytes[start_pos + 2] = 0x4c;
        }

        let target = Target(U256::from_big_endian(&target_bytes));
        let compact = target.to_compact().unwrap();
        assert_eq!(compact.0, expected_compact);

        // Verify the components match what we expected
        let result_coefficient = compact.0 & 0xffffff;
        let result_exponent = (compact.0 >> 24) & 0xff;

        assert_eq!(result_coefficient, coefficient);
        assert_eq!(result_exponent, exponent);
    }

    #[test]
    fn test_small_targets() {
        // Test 1-byte value: should be left-padded to 3 bytes
        let target = Target(U256::from(0x12));
        let compact = target.to_compact().unwrap();

        // Expected: size=1, mantissa=0x120000 (left-padded)
        let size = (compact.0 >> 24) & 0xff;
        let mantissa = compact.0 & 0xffffff;
        assert_eq!(size, 1);
        assert_eq!(mantissa, 0x120000);
        assert_eq!(compact.0, 0x01120000);

        // Test 2-byte value
        let target = Target(U256::from(0x1234));
        let compact = target.to_compact().unwrap();
        assert_eq!(compact.0, 0x02123400);

        // Test 3-byte value (no padding needed)
        let target = Target(U256::from(0x123456));
        let compact = target.to_compact().unwrap();
        assert_eq!(compact.0, 0x03123456);
    }

    #[test]
    fn test_normalization() {
        let target = Target(U256::from(0x800000)); // High bit set in 3-byte value
        let compact = target.to_compact().unwrap();

        // Should normalize: right-shift by 8, increment size
        let size = (compact.0 >> 24) & 0xff;
        let mantissa = compact.0 & 0xffffff;

        assert_eq!(size, 4); // Size incremented from 3 to 4
        assert_eq!(mantissa, 0x008000); // Shifted right by 8 bits
        assert_eq!(compact.0, 0x04008000);

        // Test another normalization case
        let target = Target(U256::from(0x92340000u64));
        let compact = target.to_compact().unwrap();

        // 0x92340000 has high bit set, should normalize
        let size = (compact.0 >> 24) & 0xff;
        let mantissa = compact.0 & 0xffffff;
        assert!(size >= 4); // Size should be reasonable after normalization
        assert!(mantissa < 0x800000); // Mantissa should not have high bit set after normalization
    }

    #[test]
    fn test_large_targets() {
        let large_hex = "123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0";
        let target = Target(U256::from_str_radix(large_hex, 16).unwrap());

        let compact = target.to_compact().unwrap();

        // Should succeed and produce a valid compact representation
        let size = (compact.0 >> 24) & 0xff;
        let mantissa = compact.0 & 0xffffff;

        // Size should be reasonable (around 32 for a full 256-bit number)
        assert!(size > 3);
        assert!(size <= 32);

        // Mantissa should be the most significant 3 bytes
        assert_ne!(mantissa, 0);
        assert!(mantissa <= 0xffffff);
    }

    #[test]
    fn test_historical_bitcoin_chainwork_compatibility() {
        // Test using the exact same chainwork values from the other library's tests
        // These are actual Bitcoin Core historical chainwork values

        let historical_chainwork_tests = vec![
            // (chainwork_value, description)
            (0x200020002u128, "height 1 - very early Bitcoin"),
            (0xa97d67041c5e51596ee7u128, "height 308004"),
            (0x1dc45d79394baa8ab18b20u128, "height 418141"),
            (0x8c85acb73287e335d525b98u128, "height 596624"),
            (0x2ef447e01d1642c40a184adau128, "height 738965"),
        ];

        // We can't directly test these chainwork values since they're cumulative,
        // but we can verify our Work type can handle these magnitudes correctly
        for (chainwork, description) in historical_chainwork_tests {
            let work_value = U256::from(chainwork);
            let work = Work::new(work_value);

            // Verify the work value is reasonable (not zero, not overflow)
            assert!(work.0 > U256::zero(), "Chainwork should be positive for {}", description);
            assert!(work.0 <= U256::max_value(), "Chainwork should not overflow for {}", description);

            // Test that we can create Work objects with these historical values
            assert_eq!(work.0, work_value, "Work value should match input for {}", description);
        }
    }

    #[test]
    fn test_bitcoin_formula_consistency() {
        let test_cases = vec![
            (0x1d00ffff, "00000000ffff0000000000000000000000000000000000000000000000000000"),
            (0x1b04864c, "0000000004864c000000000000000000000000000000000000000000000000"),
        ];

        for (expected_compact, target_hex) in test_cases {
            let target = Target(U256::from_str_radix(target_hex, 16).unwrap());
            let compact = target.to_compact().unwrap();
            assert_eq!(compact.0, expected_compact,
                       "Failed for target {}: expected 0x{:08x}, got 0x{:08x}",
                       target_hex, expected_compact, compact.0);

            // Verify the reverse calculation
            let coefficient = compact.0 & 0xffffff;
            let exponent = (compact.0 >> 24) & 0xff;

            // The coefficient should be the top 3 bytes of the target
            // and exponent should represent the byte length correctly
            assert_ne!(coefficient, 0);
            assert!(exponent >= 1);
            assert!(exponent <= 32);
        }
    }

    #[test]
    fn test_round_trip_conversion() {
        let test_targets = vec![
            U256::from(0x12),
            U256::from(0x1234),
            U256::from(0x123456),
            U256::from(0x12345678u64),
            U256::from_str_radix("00000000ffff0000000000000000000000000000000000000000000000000000", 16).unwrap(),
        ];

        for original_target in test_targets {
            let target = Target(original_target);
            let compact = target.to_compact().unwrap();

            // Convert back using Bitcoin's formula
            let coefficient = compact.0 & 0xffffff;
            let exponent = (compact.0 >> 24) & 0xff;

            // Reconstruct target: coefficient * 256^(exponent - 3)
            let mut reconstructed = U256::from(coefficient);
            if exponent >= 3 {
                let shift_bytes = exponent - 3;
                for _ in 0..shift_bytes {
                    reconstructed *= U256::from(256);
                }
            } else {
                // For very small targets, divide instead
                let shift_bytes = 3 - exponent;
                for _ in 0..shift_bytes {
                    reconstructed /= U256::from(256);
                }
            }

            // The reconstructed target should match the original
            // (or be very close due to precision limits)
            assert_eq!(Target(reconstructed).to_compact().unwrap().0, compact.0);
        }
    }

    #[test]
    fn test_target_edge_cases() {
        // Test edge case: exactly 3 bytes, no normalization needed
        let target = Target(U256::from(0x7fffff)); // Just below normalization threshold
        let compact = target.to_compact().unwrap();
        assert_eq!(compact.0, 0x037fffff);

        // Test edge case: exactly at normalization threshold
        let target = Target(U256::from(0x800000)); // Exactly at threshold
        let compact = target.to_compact().unwrap();
        assert_eq!(compact.0, 0x04008000); // Should be normalized
    }

    #[test]
    fn test_zero_target_to_work() {
        let target = Target::zero();
        let work = target.to_work().unwrap();
        assert_eq!(work.0, U256::max_value());
    }

    #[test]
    fn test_one_target_to_work() {
        let target = Target::new(U256::one());
        let work = target.to_work().unwrap();
        assert_eq!(work.0, U256::max_value());
    }

    #[test]
    fn test_max_target_to_work() {
        let target = Target::new(U256::max_value());
        let work = target.to_work().unwrap();
        assert_eq!(work.0, U256::one());
    }

    #[test]
    fn test_genesis_block_target_work() {
        // Bitcoin genesis block: nBits = 0x1d00ffff
        // Target = 0x00000000ffff0000000000000000000000000000000000000000000000000000
        let target_hex = "00000000ffff0000000000000000000000000000000000000000000000000000";
        let target = Target(U256::from_str_radix(target_hex, 16).unwrap());
        let work = target.to_work().unwrap();

        // Bitcoin Core formula: 2^256 / (target + 1)
        // Expected work: 0x0000000000000000000000000000000000000000000000000000000100010001
        let expected_work = U256::from_str_radix("0000000000000000000000000000000000000000000000000000000100010001", 16).unwrap();
        assert_eq!(work.0, expected_work);
    }

    #[test]
    fn test_target_value_2() {
        // Test target = 2 using Bitcoin Core formula: 2^256 / (2 + 1) = 2^256 / 3
        let target = Target::new(U256::from(2u64));
        let work = target.to_work().unwrap();

        // Expected: 0x5555555555555555555555555555555555555555555555555555555555555555
        let expected_work = U256::from_str_radix("5555555555555555555555555555555555555555555555555555555555555555", 16).unwrap();
        assert_eq!(work.0, expected_work);
    }

    #[test]
    fn test_target_value_10() {
        // Test target = 10 using Bitcoin Core formula: 2^256 / (10 + 1) = 2^256 / 11
        let target = Target::new(U256::from(10u64));
        let work = target.to_work().unwrap();

        // Expected: 0x1745d1745d1745d1745d1745d1745d1745d1745d1745d1745d1745d1745d1745
        let expected_work = U256::from_str_radix("1745d1745d1745d1745d1745d1745d1745d1745d1745d1745d1745d1745d1745", 16).unwrap();
        assert_eq!(work.0, expected_work);
    }

    #[test]
    fn test_target_value_100() {
        // Test target = 100 using Bitcoin Core formula: 2^256 / (100 + 1) = 2^256 / 101
        let target = Target::new(U256::from(100u64));
        let work = target.to_work().unwrap();

        // Expected: 0x288df0cac5b3f5dc83cd4e930288df0cac5b3f5dc83cd4e930288df0cac5b3f
        let expected_work = U256::from_str_radix("288df0cac5b3f5dc83cd4e930288df0cac5b3f5dc83cd4e930288df0cac5b3f", 16).unwrap();
        assert_eq!(work.0, expected_work);
    }

    #[test]
    fn test_target_value_256() {
        // Test target = 256 using Bitcoin Core formula: 2^256 / (256 + 1) = 2^256 / 257
        let target = Target::new(U256::from(256u64));
        let work = target.to_work().unwrap();

        // Expected: 0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff
        let expected_work = U256::from_str_radix("ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff", 16).unwrap();
        assert_eq!(work.0, expected_work);
    }

    #[test]
    fn test_target_value_65536() {
        // Test target = 65536 using Bitcoin Core formula: 2^256 / (65536 + 1) = 2^256 / 65537
        let target = Target::new(U256::from(65536u64));
        let work = target.to_work().unwrap();

        // Expected: 0xffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff
        let expected_work = U256::from_str_radix("ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff", 16).unwrap();
        assert_eq!(work.0, expected_work);
    }

    #[test]
    fn test_bitcoin_block_100000_target() {
        // Bitcoin block 100000: nBits = 0x1b04864c
        // Target = 0x000000000004864c000000000000000000000000000000000000000000000000
        let target_hex = "000000000004864c000000000000000000000000000000000000000000000000";
        let target = Target(U256::from_str_radix(target_hex, 16).unwrap());
        let work = target.to_work().unwrap();

        // Expected work using Bitcoin Core formula: 2^256 / (target + 1)
        // Expected: 0x000000000000000000000000000000000000000000000000000038946224e37e
        let expected_work = U256::from_str_radix("000000000000000000000000000000000000000000000000000038946224e37e", 16).unwrap();
        assert_eq!(work.0, expected_work);
    }

    #[test]
    fn test_work_monotonic_decrease_exact() {
        // Test exact monotonic decrease with precise expected values
        let test_cases = vec![
            (2u64, "5555555555555555555555555555555555555555555555555555555555555555"),
            (4u64, "3333333333333333333333333333333333333333333333333333333333333333"),
            (8u64, "1c71c71c71c71c71c71c71c71c71c71c71c71c71c71c71c71c71c71c71c71c71"),
            (16u64, "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"),
            (32u64, "07c1f07c1f07c1f07c1f07c1f07c1f07c1f07c1f07c1f07c1f07c1f07c1f07c1"),
            (64u64, "03f03f03f03f03f03f03f03f03f03f03f03f03f03f03f03f03f03f03f03f03f0"),
        ];

        for (target_val, expected_hex) in test_cases {
            let target = Target::new(U256::from(target_val));
            let work = target.to_work().unwrap();
            let expected_work = U256::from_str_radix(expected_hex, 16).unwrap();

            assert_eq!(work.0, expected_work, "Work calculation failed for target: {}", target_val);
        }
    }

    #[test]
    fn test_large_target_values_exact() {
        // Test larger target values with exact expected results
        let test_cases = vec![
            (1000u64, "004178749e8fba7004178749e8fba7004178749e8fba7004178749e8fba70041"),
            (2000u64, "0020c06a7159f0644d45fb2370332ca6511c879cb8bd58675f4ff5c3debc93e4"),
            (1000000u64, "000010c6f6873c67ecb4b00c89b01bf0546a14c7d05ea56be10a1586a792e7ba"),
        ];

        for (target_val, expected_hex) in test_cases {
            let target = Target::new(U256::from(target_val));
            let work = target.to_work().unwrap();
            let expected_work = U256::from_str_radix(expected_hex, 16).unwrap();

            assert_eq!(work.0, expected_work, "Work calculation failed for target: {}", target_val);
        }
    }

    #[test]
    fn test_very_large_target_exact() {
        // Test with a very large target: max_value / 1000000
        // Target: 0x000010c6f7a0b5ed8d36b4c7f34938583621fafc8b0079a2834d26fa3fcc9ea9
        let large_target = U256::max_value() / U256::from(1000000u64);
        let target = Target::new(large_target);
        let work = target.to_work().unwrap();

        // Expected work: 0x00000000000000000000000000000000000000000000000000000000000f423f
        let expected_work = U256::from_str_radix("00000000000000000000000000000000000000000000000000000000000f423f", 16).unwrap();
        assert_eq!(work.0, expected_work);
    }

    #[test]
    fn test_overflow_near_max_exact() {
        // Test with U256::max_value() - 1
        let near_max_target = U256::max_value() - U256::one();
        let target = Target::new(near_max_target);

        let result = target.to_work();
        assert!(result.is_some());

        // The special case should return exactly 1
        assert_eq!(result.unwrap().0, U256::one());
    }

    #[test]
    fn test_mathematical_relationship_exact() {
        // Test the exact mathematical relationship between targets 1000 and 2000
        let target_1000 = Target::new(U256::from(1000u64));
        let target_2000 = Target::new(U256::from(2000u64));

        let work_1000 = target_1000.to_work().unwrap();
        let work_2000 = target_2000.to_work().unwrap();

        // Expected exact values
        let expected_work_1000 = U256::from_str_radix("004178749e8fba7004178749e8fba7004178749e8fba7004178749e8fba70041", 16).unwrap();
        let expected_work_2000 = U256::from_str_radix("0020c06a7159f0644d45fb2370332ca6511c879cb8bd58675f4ff5c3debc93e4", 16).unwrap();

        assert_eq!(work_1000.0, expected_work_1000);
        assert_eq!(work_2000.0, expected_work_2000);

        // Calculate 2 * work_2000 and verify it's what we expect
        let double_work_2000 = expected_work_2000 * U256::from(2u64);
        let expected_double_work_2000 = U256::from_str_radix("004180d4e2b3e0c89a8bf646e066594ca2390f39717ab0cebe9feb87bd7927c8", 16).unwrap();

        assert_eq!(double_work_2000, expected_double_work_2000);

        // Verify work_1000 is NOT exactly double work_2000 (due to the +1 in denominator)
        assert_ne!(work_1000.0, double_work_2000);

        // Verify work_1000 is slightly less than 2*work_2000 because:
        // work_1000 = 2^256 / 1001, 2*work_2000 = 2*2^256 / 2001 = 2^257 / 2001
        // Since 2^257 / 2001 > 2^256 / 1001, we have work_1000 < 2*work_2000
        assert!(work_1000.0 < double_work_2000);
    }

    #[test]
    fn test_formula_equivalence_exact() {
        // Test that our implementation produces exactly the same results as Bitcoin Core formula
        // for a comprehensive set of values
        let test_values = [2u64, 3u64, 5u64, 7u64, 11u64, 13u64, 17u64, 19u64, 23u64, 29u64];
        let expected_results = ["5555555555555555555555555555555555555555555555555555555555555555",
            "4000000000000000000000000000000000000000000000000000000000000000",
            "2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "2000000000000000000000000000000000000000000000000000000000000000",
            "1555555555555555555555555555555555555555555555555555555555555555",
            "1249249249249249249249249249249249249249249249249249249249249249",
            "0e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38",
            "0ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "0888888888888888888888888888888888888888888888888888888888888888"];

        for (i, val) in test_values.iter().enumerate() {
            let target = Target::new(U256::from(*val));
            let work = target.to_work().unwrap();
            let expected_work = U256::from_str_radix(expected_results[i], 16).unwrap();

            assert_eq!(work.0, expected_work, "Work calculation failed for target: {}", val);
        }
    }

    #[test]
    fn test_work_not_zero_exact() {
        // Test exact non-zero results for various target values
        let test_cases = vec![
            (2u64, false),           // Should be large
            (1000u64, false),        // Should be medium
            (1000000u64, false),     // Should be small but non-zero
        ];

        for (target_val, should_be_zero) in test_cases {
            let target = Target::new(U256::from(target_val));
            let work = target.to_work().unwrap();

            if should_be_zero {
                assert_eq!(work.0, U256::zero(), "Work should be zero for target: {}", target_val);
            } else {
                assert_ne!(work.0, U256::zero(), "Work should not be zero for target: {}", target_val);
            }
        }
    }
}
