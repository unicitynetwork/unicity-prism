//! Bitcoin P2P node implementation for Unicity Prism.
//!
//! This module implements a Bitcoin P2P node that can connect to peers,
//! perform handshakes, and synchronize blockchain data.

use std::{net::SocketAddr, str::FromStr};

use clap::Parser;
use tracing::{debug, error, info};
use tracing_subscriber::EnvFilter;
use unicity_prism_common::alpha::{
    blockdata::block::BitcoinHeader,
    client::{
        BlockSynchronizer, ConnectionConfig, ConnectionError, ConnectionManager, HandshakeHandler,
        SyncConfig,
    },
    network::Network,
    p2p::ServiceFlags,
};

/// Command line arguments for the P2P node.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Network to connect to (mainnet, testnet, regtest)
    #[arg(short, long, default_value = "testnet")]
    network: String,

    /// Peer addresses to connect to (format: host:port)
    #[arg(short, long, value_delimiter = ',')]
    connect: Vec<String>,

    /// Maximum number of connections to maintain
    #[arg(short, long, default_value = "5")]
    max_connections: usize,

    /// Block height to start syncing from
    #[arg(long, default_value = "0")]
    start_height: u32,

    /// Maximum number of blocks to sync
    #[arg(long, default_value = "1000")]
    max_blocks: u32,

    /// User agent string to advertise
    #[arg(long, default_value = "/unicity-prism:0.1.0/")]
    user_agent: String,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Connection timeout in seconds
    #[arg(long, default_value = "30")]
    connect_timeout: u64,

    /// Read timeout in seconds
    #[arg(long, default_value = "60")]
    read_timeout: u64,

    /// Write timeout in seconds
    #[arg(long, default_value = "30")]
    write_timeout: u64,

    /// Whether to download full blocks or just headers
    #[arg(long, default_value = "true")]
    download_full_blocks: bool,
}

/// Initializes tracing with the specified log level.
fn init_tracing(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_file(true)
        .with_line_number(true)
        .with_max_level(tracing::Level::DEBUG)
        .init();

    info!("Logging initialized with level: {}", args.log_level);
    if args.log_level == "debug" || args.log_level == "trace" {
        info!("Debug logging enabled - detailed message information will be shown");
    }

    Ok(())
}

/// Parses network string into Network enum.
fn parse_network(network_str: &str) -> Result<Network, Box<dyn std::error::Error>> {
    match network_str.to_lowercase().as_str() {
        "mainnet" | "alpha" => Ok(Network::Mainnet),
        "testnet" | "alphatestnet" => Ok(Network::Testnet),
        "regtest" | "alpharegtest" => Ok(Network::Regtest),
        _ => Err(format!(
            "Invalid network: {}. Supported networks: mainnet/alpha, testnet/alphatestnet, \
             regtest/alpharegtest",
            network_str
        )
        .into()),
    }
}

/// Parses peer address strings into SocketAddr values.
fn parse_peer_addresses(
    peer_strs: &[String],
) -> Result<Vec<SocketAddr>, Box<dyn std::error::Error>> {
    let mut addrs = Vec::new();

    for peer_str in peer_strs {
        let addr = SocketAddr::from_str(peer_str)?;
        addrs.push(addr);
    }

    Ok(addrs)
}

/// Gets default peer addresses for the specified network.
fn get_default_peers(network: Network) -> Vec<SocketAddr> {
    // Unicity Alpha testnet peers (using port 8590 as per chainparams)
    let testnet_peers = [
        "alpha-testnet.unicity.network:8590",
        "seed-alpha-testnet.unicity.network:8590",
    ];

    // Unicity Alpha mainnet peers (using port 8590 as per chainparams)
    let mainnet_peers = [
        "alpha-mainnet.unicity.network:8590",
        "seed-alpha-mainnet.unicity.network:8590",
        "node1.unicity.network:8590",
        "node2.unicity.network:8590",
        "node3.unicity.network:8590",
    ];

    // Unicity Alpha regtest peers
    let regtest_peers = ["127.0.0.1:18590"];

    let peers = match network {
        Network::Testnet => &testnet_peers[..],
        Network::Mainnet => &mainnet_peers[..],
        Network::Regtest => &regtest_peers[..],
    };

    peers.iter().filter_map(|addr| addr.parse().ok()).collect()
}

/// Connects to a peer and performs synchronization.
async fn connect_and_sync(
    connection_manager: &ConnectionManager,
    handshake_handler: &HandshakeHandler,
    block_synchronizer: &BlockSynchronizer,
    peer_addr: SocketAddr,
) -> Result<(), ConnectionError> {
    info!("Connecting to peer: {}", peer_addr);
    debug!(
        "Connection manager network: {:?}",
        connection_manager.network()
    );
    debug!(
        "Connection manager magic: {:02x?}",
        u32::from_le_bytes(connection_manager.magic().to_bytes())
    );

    // Check if we're connecting to a mainnet peer with a testnet magic or vice
    // versa
    if connection_manager.network() == Network::Mainnet {
        debug!(
            "Connecting to mainnet with mainnet magic: {:02x?}",
            u32::from_le_bytes(connection_manager.magic().to_bytes())
        );
    } else if connection_manager.network() == Network::Testnet {
        debug!(
            "Connecting to testnet with testnet magic: {:02x?}",
            u32::from_le_bytes(connection_manager.magic().to_bytes())
        );
    }

    // Establish TCP connection
    let mut stream = connection_manager.connect(peer_addr).await?;
    info!("Successfully connected to peer: {}", peer_addr);

    // Perform handshake
    debug!("Starting handshake with peer: {}", peer_addr);
    let peer_info = handshake_handler
        .perform_handshake::<BitcoinHeader>(connection_manager, &mut stream, peer_addr)
        .await?;
    info!(
        "Handshake completed with peer: {} (version: {}, height: {}, user_agent: {})",
        peer_addr, peer_info.version, peer_info.best_height, peer_info.user_agent
    );

    // Start block synchronization
    debug!("Starting block synchronization with peer: {}", peer_addr);
    match block_synchronizer
        .start_sync::<BitcoinHeader>(connection_manager, &mut stream, peer_info.best_height)
        .await
    {
        Ok(_) => {
            info!("Synchronization completed with peer: {}", peer_addr);
        }
        Err(e) => {
            error!("Synchronization failed with peer {}: {}", peer_addr, e);
            return Err(e);
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    init_tracing(&args)?;

    // Parse network
    let network = parse_network(&args.network)?;
    info!("Starting P2P client on {} network", network.as_str());

    // Parse peer addresses
    let peer_addresses = if args.connect.is_empty() {
        info!(
            "No specific peers provided, using default peers for {}",
            network.as_str()
        );
        get_default_peers(network)
    } else {
        parse_peer_addresses(&args.connect)?
    };

    // Limit number of peers to max_connections
    let peer_addresses = peer_addresses
        .into_iter()
        .take(args.max_connections)
        .collect::<Vec<_>>();

    info!("Connecting to {} peers", peer_addresses.len());

    // Create connection manager
    let connection_config = ConnectionConfig {
        network,
        connect_timeout: std::time::Duration::from_secs(args.connect_timeout),
        read_timeout: std::time::Duration::from_secs(args.read_timeout),
        write_timeout: std::time::Duration::from_secs(args.write_timeout),
        max_message_size: 32 * 1024 * 1024, // 32 MB
    };
    let connection_manager = ConnectionManager::new(connection_config);

    // Create handshake handler
    debug!(
        "Creating handshake handler with services: {:?}",
        ServiceFlags::NONE
    );
    let handshake_handler = HandshakeHandler::new(
        args.user_agent.clone(),
        i32::try_from(args.start_height).unwrap_or(0),
    )
    .with_services(ServiceFlags::NONE);
    debug!(
        "Handshake handler created with services: {:?}",
        ServiceFlags::NONE
    );

    // Create block synchronizer
    let sync_config = SyncConfig {
        max_headers_per_request: 2000,
        max_blocks_to_download: args.max_blocks as usize,
        download_full_blocks: args.download_full_blocks,
    };
    let block_synchronizer = BlockSynchronizer::new(sync_config);

    // Connect to peers and start synchronization
    let mut successful_connections = 0usize;
    for peer_addr in &peer_addresses {
        match connect_and_sync(
            &connection_manager,
            &handshake_handler,
            &block_synchronizer,
            *peer_addr,
        )
        .await
        {
            Ok(_) => {
                successful_connections = successful_connections.saturating_add(1);
                info!("Successfully synced with peer: {}", peer_addr);
            }
            Err(e) => {
                error!("Failed to sync with peer {}: {}", peer_addr, e);
            }
        }
    }

    // Print final statistics
    let progress = block_synchronizer.get_progress().await;
    info!(
        "Synchronization complete. Connected to {}/{} peers. Synced {} headers and {} blocks.",
        successful_connections,
        args.max_connections,
        progress.headers_synced,
        progress.blocks_downloaded
    );

    // NOTE: KEEP THIS COMMENTED OUT FOR NOW - KEEP-ALIVE MECHANISM
    // info!("Starting keep-alive mechanism...");
    // let keep_alive_interval = std::time::Duration::from_secs(30); // Send ping every 30 seconds
    //
    // // Create a vector to store active connections for keep-alive
    // let mut active_connections = Vec::new();
    //
    // // Reconnect to peers for keep-alive
    // for peer_addr in peer_addresses {
    //     match connection_manager.connect(peer_addr).await {
    //         Ok(mut stream) => {
    //             info!("Reconnected to peer for keep-alive: {}", peer_addr);
    //
    //             // Perform handshake again
    //             match handshake_handler
    //                 .perform_handshake::<BitcoinHeader>(&connection_manager, &mut stream, peer_addr)
    //                 .await
    //             {
    //                 Ok(peer_info) => {
    //                     info!(
    //                         "Handshake completed for keep-alive with peer: {}",
    //                         peer_addr
    //                     );
    //                     active_connections.push((peer_addr, stream, peer_info));
    //                 }
    //                 Err(e) => {
    //                     error!("Keep-alive handshake failed with peer {}: {}", peer_addr, e);
    //                 }
    //             }
    //         }
    //         Err(e) => {
    //             error!(
    //                 "Failed to reconnect to peer {} for keep-alive: {}",
    //                 peer_addr, e
    //             );
    //         }
    //     }
    // }
    //
    // if active_connections.is_empty() {
    //     warn!("No active connections available for keep-alive mechanism");
    // } else {
    //     info!(
    //         "Keep-alive mechanism started with {} active connections",
    //         active_connections.len()
    //     );
    //
    //     // Run keep-alive loop
    //     let mut ping_counter = 0;
    //     loop {
    //         tokio::time::sleep(keep_alive_interval).await;
    //         ping_counter += 1;
    //
    //         info!(
    //             "Sending keep-alive ping #{} to {} peers",
    //             ping_counter,
    //             active_connections.len()
    //         );
    //
    //         for (peer_addr, stream, _) in &mut active_connections {
    //             let ping = unicity_prism_common::alpha::client::message::connection::Ping::new();
    //             let message =
    //                 unicity_prism_common::alpha::client::Message::<BitcoinHeader>::Connection(
    //                     unicity_prism_common::alpha::client::message::Connection::Ping(ping),
    //                 );
    //
    //             match connection_manager.send_message(stream, message).await {
    //                 Ok(_) => {
    //                     debug!("Keep-alive ping sent to peer: {}", peer_addr);
    //                 }
    //                 Err(e) => {
    //                     error!(
    //                         "Failed to send keep-alive ping to peer {}: {}",
    //                         peer_addr, e
    //                     );
    //                 }
    //             }
    //         }
    //     }
    // }

    Ok(())
}
