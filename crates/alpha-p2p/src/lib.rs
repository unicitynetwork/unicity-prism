mod blockdata;
mod consensus;
mod io;
mod network;
mod p2p;
mod params;

use crate::blockdata::block::Block;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::Instant;

const PROTOCOL_VERSION: u32 = 70015;
const NODE_NETWORK: u8 = 1;
const NODE_WITNESS: u8 = 1 << 3; // This is 8 in decimal
const MAX_PROTOCOL_MESSAGE_LENGTH: usize = 32 * 1024 * 1024; // 32 MB
const TIMEOUT_INTERVAL: Duration = Duration::from_secs(20 * 60); // 20 minutes in seconds
const CLIENT_USER_AGENT: &str = "/PrismClient:0.1.0/";

pub enum Message {
    VERSION,
    VERACK,
    GETBLOCKS,
    INV,
    GETDATA,
    BLOCK,
    PING,
    PONG,
    HEADERS,
    GETHEADERS,
}

impl Message {
    pub fn as_command(&self) -> &[u8; 12] {
        match self {
            Message::VERSION => b"version\0\0\0\0\0",
            Message::VERACK => b"verack\0\0\0\0\0\0",
            Message::GETBLOCKS => b"getblocks\0\0\0",
            Message::INV => b"inv\0\0\0\0\0\0\0\0\0",
            Message::GETDATA => b"getdata\0\0\0\0\0",
            Message::BLOCK => b"block\0\0\0\0\0\0\0",
            Message::PING => b"ping\0\0\0\0\0\0\0\0",
            Message::PONG => b"pong\0\0\0\0\0\0\0\0",
            Message::HEADERS => b"headers\0\0\0\0\0",
            Message::GETHEADERS => b"getheaders\0\0",
        }
    }
}

pub struct AlphaClient {
    stream: Option<TcpStream>,
    peer_address: SocketAddr,
    local_nonce: u64,
    peer_version: Option<u32>,
    handshake_complete: AtomicBool,
    connected: AtomicBool,

    // Block chain state
    blockchain: Mutex<Vec<Block>>,
    best_height: AtomicU32,
    genesis_hash: [u8; 32],
    last_block_hash: Mutex<[u8; 32]>,

    // Network statistics
    bytes_sent: AtomicU32,
    bytes_received: AtomicU32,
    last_ping_time: Mutex<Option<Instant>>,

    // Configuration
    services: u64,
    start_height: u32,
}

impl AlphaClient {
    pub fn new() -> Self {
        Self {
            stream: None,
            peer_address: (),
            local_nonce: 0,
            peer_version: None,
            handshake_complete: Default::default(),
            connected: Default::default(),
            blockchain: Default::default(),
            best_height: Default::default(),
            genesis_hash: [],
            last_block_hash: Default::default(),
            bytes_sent: Default::default(),
            bytes_received: Default::default(),
            last_ping_time: Default::default(),
            services: 0,
            start_height: 0,
        }
    }

    pub async fn connect(&mut self, addr: &str) -> tokio::io::Result<()> {
        let stream = TcpStream::connect(addr).await?;
        self.stream = Some(stream);
        Ok(())
    }

    pub async fn handshake(&mut self) -> tokio::io::Result<()> {
        // if let Some(stream) = &mut self.stream {
        //     let version_message = self.create_version_message();
        //     stream.write_all(&version_message).await?;
        //     // Read and process the response (verack message)
        //     let mut buffer = [0u8; 1024];
        //     let n = stream.read(&mut buffer).await?;
        //     // Here you would parse the response and verify it's a verack message
        //     println!("Received {} bytes", n);
        // }
        Ok(())
    }

    fn create_version_message(&self) -> Vec<u8> {
        let mut message = Vec::new();
        // Magic bytes
        message.extend_from_slice(&MAGIC_MAINNET);
        // Command "version"
        let command = b"version\0\0\0\0\0\0\0\0";
        message.extend_from_slice(command);
        // Payload length (fixed size for version message)
        let payload_length = 86u32;
        message.extend_from_slice(&payload_length.to_le_bytes());
        // Checksum (placeholder, should be calculated)
        let checksum = [0u8; 4];
        message.extend_from_slice(&checksum);
        // Payload
        message.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        message.extend_from_slice(&NODE_NETWORK.to_le_bytes());
        // Add more fields as per the Bitcoin protocol specification
        // For simplicity, we are not adding all fields here
        message
    }
}
