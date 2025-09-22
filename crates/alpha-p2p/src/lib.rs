mod blockdata;
mod consensus;
mod hashes;
mod io;
pub mod network;
mod p2p;
mod pow;

pub use network::Network;

use std::time::Duration;

const PROTOCOL_VERSION: u32 = 70015;
const NODE_NETWORK: u8 = 1;
const NODE_WITNESS: u8 = 1 << 3; // This is 8 in decimal
const MAX_PROTOCOL_MESSAGE_LENGTH: usize = 32 * 1024 * 1024; // 32 MB
const TIMEOUT_INTERVAL: Duration = Duration::from_secs(20 * 60); // 20 minutes in seconds
const CLIENT_USER_AGENT: &str = "/PrismClient:0.1.0/";
