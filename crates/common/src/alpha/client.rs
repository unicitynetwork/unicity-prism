//! Client module for Alpha P2P protocol implementation.
//!
//! This module provides the core client functionality for connecting to Alpha
//! peers, performing handshakes, and synchronizing blockchain data.

pub mod connection;
pub mod database;
pub mod handshake;
pub mod message;
pub mod network;
pub mod peer;
pub mod sync;

pub use connection::{ConnectionConfig, ConnectionError, ConnectionManager};
pub use database::{
    BlockDatabase, ChainState as DatabaseChainState, DatabaseError, DatabaseResult,
};
pub use handshake::{HandshakeHandler, PeerInfo};
pub use message::{Connection, Message, Request, Response};
pub use sync::{BlockSynchronizer, SyncConfig, SyncProgress};
