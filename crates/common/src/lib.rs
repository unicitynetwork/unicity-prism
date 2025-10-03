//! Alpha P2P library for Alpha protocol implementation.
//!
//! This library provides a comprehensive implementation of the Alpha P2P
//! protocol, including message types, connection management, handshake
//! protocol, and block synchronization functionality.

#![cfg_attr(test, allow(clippy::arithmetic_side_effects))]
#![cfg_attr(test, allow(clippy::unwrap_used))]
#![cfg_attr(test, allow(clippy::expect_used))]
#![cfg_attr(test, allow(clippy::arithmetic_side_effects))]
#![cfg_attr(test, allow(clippy::cast_sign_loss))]
#![cfg_attr(test, allow(clippy::indexing_slicing))]
#![cfg_attr(test, allow(clippy::panic))]
#![cfg_attr(test, allow(clippy::cast_possible_truncation))]

/// Types and functions related to the Alpha protocol.
pub mod alpha;

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
