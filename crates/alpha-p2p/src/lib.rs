//! Alpha P2P library for Alpha protocol implementation.
//!
//! This library provides a comprehensive implementation of the Alpha P2P protocol,
//! including message types, connection management, handshake protocol, and block
//! synchronization functionality.

#![cfg_attr(test, allow(clippy::arithmetic_side_effects))]
#![cfg_attr(test, allow(clippy::unwrap_used))]
#![cfg_attr(test, allow(clippy::expect_used))]
#![cfg_attr(test, allow(clippy::arithmetic_side_effects))]
#![cfg_attr(test, allow(clippy::cast_sign_loss))]
#![cfg_attr(test, allow(clippy::indexing_slicing))]
#![cfg_attr(test, allow(clippy::panic))]
#![cfg_attr(test, allow(clippy::cast_possible_truncation))]

/// Block data structures for Bitcoin protocol.
pub mod blockdata;
/// Client implementation for Bitcoin P2P network communication.
pub mod client;
/// Consensus encoding and decoding functionality.
pub mod consensus;
/// Hash functions and types used in Bitcoin.
pub mod hashes;
/// I/O utilities for reading and writing data.
pub mod io;
/// Network types and constants.
pub mod network;
/// Peer-to-peer protocol implementation.
pub mod p2p;
/// Proof of Work related functionality.
pub mod pow;
/// Utility functions and types.
pub mod util;

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
