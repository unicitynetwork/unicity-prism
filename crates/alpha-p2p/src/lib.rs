#![cfg_attr(test, allow(clippy::integer_arithmetic))]
#![cfg_attr(test, allow(clippy::unwrap_used))]
#![cfg_attr(test, allow(clippy::expect_used))]
#![cfg_attr(test, allow(clippy::arithmetic_side_effects))]
#![cfg_attr(test, allow(clippy::cast_sign_loss))]
#![cfg_attr(test, allow(clippy::indexing_slicing))]

pub mod blockdata;
mod client;
mod consensus;
mod hashes;
mod io;
pub mod network;
mod p2p;
pub mod pow;
mod util;

pub use network::Network;

use std::time::Duration;

const PROTOCOL_VERSION: u32 = 70016;
const NODE_NETWORK: u8 = 1;
const NODE_WITNESS: u8 = 1 << 3; // This is 8 in decimal
const MAX_PROTOCOL_MESSAGE_LENGTH: usize = 32 * 1024 * 1024; // 32 MB
const TIMEOUT_INTERVAL: Duration = Duration::from_secs(20 * 60); // 20 minutes in seconds
const CLIENT_USER_AGENT: &str = "/PrismClient:0.1.0/";
