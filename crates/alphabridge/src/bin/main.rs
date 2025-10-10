//! Bitcoin P2P node implementation for Unicity Prism.
//!
//! This module implements a Bitcoin P2P node that can connect to peers,
//! perform handshakes, and synchronize blockchain data.

use std::{net::SocketAddr, path::PathBuf, str::FromStr, sync::Arc};

use clap::Parser;
use directories::ProjectDirs;
use tokio::{io::AsyncWriteExt, sync::RwLock};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;
use unicity_prism_common::alpha::{
    blockdata::block::BitcoinHeader,
    client::{
        BlockDatabase, BlockSynchronizer, ConnectionConfig, ConnectionError, ConnectionManager,
        HandshakeHandler, SyncConfig,
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

    /// Data directory for persistent storage
    #[arg(long)]
    data_dir: Option<String>,

    /// Whether to continuously monitor for new blocks
    #[arg(long, default_value = "true")]
    continuous_sync: bool,

    /// Interval for checking new blocks (in seconds)
    #[arg(long, default_value = "30")]
    sync_interval: u64,
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

/// Gets the default application data directory based on the platform.
fn get_default_data_dir() -> Option<PathBuf> {
    if let Some(proj_dirs) = ProjectDirs::from("org", "unicitylabs", "prism") {
        Some(proj_dirs.data_dir().to_path_buf())
    } else {
        None
    }
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

    // Determine data directory
    let data_dir = match args.data_dir {
        Some(dir) => {
            info!("Using custom data directory: {}", dir);
            Some(PathBuf::from(dir))
        }
        None => match get_default_data_dir() {
            Some(dir) => {
                info!("Using default data directory: {}", dir.display());
                Some(dir)
            }
            None => {
                warn!("Could not determine default data directory, using memory-only mode");
                None
            }
        },
    };

    // Create network-specific data directory
    let network_data_dir = if let Some(base_dir) = data_dir {
        let network_dir = base_dir.join(match network {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
            Network::Regtest => "regtest",
        });

        // Create directory if it doesn't exist
        if let Err(e) = tokio::fs::create_dir_all(&network_dir).await {
            error!(
                "Failed to create data directory {}: {}",
                network_dir.display(),
                e
            );
            None
        } else {
            info!(
                "Using network-specific data directory: {}",
                network_dir.display()
            );
            Some(network_dir)
        }
    } else {
        None
    };

    // Set up signal handling for graceful shutdown
    let cancel_token = CancellationToken::new();
    let signal_token = cancel_token.clone();

    // Create block synchronizer with database
    let sync_config = SyncConfig {
        max_headers_per_request: 2000,
        max_blocks_to_download: if args.max_blocks == 1000 {
            usize::MAX
        } else {
            args.max_blocks as usize
        },
        download_full_blocks: args.download_full_blocks,
        data_dir: network_data_dir.clone(),
        continuous_sync: args.continuous_sync,
        sync_interval: args.sync_interval,
        max_retries: 3,
        request_timeout: std::time::Duration::from_secs(60),
    };

    // Initialize database if data directory is provided
    let block_synchronizer = if let Some(ref data_dir) = sync_config.data_dir {
        let db_path = PathBuf::from(data_dir).join("blockchain.db");
        info!("Initializing blockchain database at: {}", db_path.display());

        match BlockDatabase::open(&db_path).await {
            Ok(database) => {
                info!("Database opened successfully");
                let db = Arc::new(database);

                // Migrate from JSON if needed
                if let Err(e) = db.migrate_from_json(data_dir).await {
                    warn!("Failed to migrate from JSON: {}", e);
                }

                let mut sync = BlockSynchronizer::with_database(sync_config, db);
                // Update the synchronizer with our cancellation token
                sync.set_cancel_token(cancel_token.clone());
                sync
            }
            Err(e) => {
                error!(
                    "Failed to open database: {}, falling back to memory-only mode",
                    e
                );
                let mut sync = BlockSynchronizer::new(sync_config);
                sync.set_cancel_token(cancel_token.clone());
                sync
            }
        }
    } else {
        info!("No data directory available, using memory-only mode");
        let mut sync = BlockSynchronizer::new(sync_config);
        sync.set_cancel_token(cancel_token.clone());
        sync
    };

    // Handle Ctrl+C
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.unwrap_or_default();
        warn!("Received Ctrl+C, initiating shutdown...");
        signal_token.cancel();
    });

    // Handle termination signal (for systemd, docker, etc.)
    let term_token = cancel_token.clone();
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sigterm = signal(SignalKind::terminate()).unwrap();
            sigterm.recv().await;
            warn!("Received SIGTERM, initiating shutdown...");
            term_token.cancel();
        }
        #[cfg(not(unix))]
        {
            // On Windows, we only have Ctrl+C handling
        }
    });

    // Connect to peers and start synchronization
    let mut successful_connections = 0usize;
    let mut active_streams = Vec::new();
    let mut join_handles = Vec::new();

    // Clone peer_addresses to avoid borrowing issues
    let _peer_addresses_clone = peer_addresses.clone();

    for peer_addr in &peer_addresses {
        if cancel_token.is_cancelled() {
            info!("Cancellation detected, stopping new connections");
            break;
        }

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

                // Keep the connection alive for continuous sync
                if args.continuous_sync {
                    match connection_manager.connect(*peer_addr).await {
                        Ok(mut stream) => {
                            if let Ok(peer_info) = handshake_handler
                                .perform_handshake::<BitcoinHeader>(
                                    &connection_manager,
                                    &mut stream,
                                    *peer_addr,
                                )
                                .await
                            {
                                active_streams.push((peer_addr, stream, peer_info));
                            }
                        }
                        Err(e) => {
                            error!("Failed to reconnect to peer {}: {}", peer_addr, e);
                        }
                    }
                }
            }
            Err(e) => {
                error!("Failed to sync with peer {}: {}", peer_addr, e);
            }
        }
    }

    // If continuous sync is enabled, start monitoring
    if args.continuous_sync && !active_streams.is_empty() {
        info!(
            "Starting continuous synchronization with {} peers",
            active_streams.len()
        );

        // Create a child token for the monitoring task
        let monitor_token = cancel_token.child_token();
        let sync_clone = block_synchronizer.clone();

        let monitor_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));

            loop {
                tokio::select! {
                    _ = monitor_token.cancelled() => {
                        info!("Monitor task cancelled");
                        break;
                    }
                    _ = interval.tick() => {
                        // Print progress periodically
                        let progress = sync_clone.get_progress().await;
                        if progress.headers_synced > 0 && progress.headers_synced % 100 == 0 {
                            info!(
                                "Sync progress: {} headers, {} blocks, current height: {}, sync rate: {:.2} headers/sec",
                                progress.headers_synced,
                                progress.blocks_downloaded,
                                progress.current_height,
                                progress.sync_rate
                            );
                        }

                        // Check if synchronizer is still monitoring
                        if !progress.is_monitoring {
                            info!("Synchronizer is no longer monitoring");
                            break;
                        }
                    }
                }
            }
        });

        join_handles.push(monitor_handle);
    }

    // Wait for cancellation
    cancel_token.cancelled().await;
    info!("Shutdown initiated");

    // Abort all tasks with a short timeout
    for handle in &join_handles {
        handle.abort();
    }

    // Shutdown synchronizer
    info!("Shutting down block synchronizer...");
    block_synchronizer.shutdown().await;

    // Close any remaining active connections
    while let Some((peer_addr, mut stream, _)) = active_streams.pop() {
        let _ = stream.shutdown().await;
        info!("Closed connection to {}", peer_addr);
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

    // Wait for all spawned tasks to complete with timeout
    info!("Waiting for all tasks to complete...");
    for handle in join_handles {
        match tokio::time::timeout(std::time::Duration::from_secs(5), handle).await {
            Ok(Ok(_)) => {
                debug!("Task completed successfully");
            }
            Ok(Err(e)) => {
                error!("Task failed during shutdown: {}", e);
            }
            Err(_) => {
                warn!("Task didn't complete within timeout, continuing shutdown");
            }
        }
    }

    // Close any remaining active connections with timeout
    for (peer_addr, mut stream, _) in active_streams {
        // Try to close the connection, but don't wait too long
        match tokio::time::timeout(std::time::Duration::from_millis(500), stream.shutdown()).await {
            Ok(Ok(_)) => {
                info!("Closed connection to {}", peer_addr);
            }
            Ok(Err(e)) => {
                error!("Failed to close connection to {}: {}", peer_addr, e);
            }
            Err(_) => {
                warn!(
                    "Timeout closing connection to {} (continuing shutdown)",
                    peer_addr
                );
                // Just continue with shutdown, TcpStream will be closed when
                // dropped
            }
        }
    }

    info!("Graceful shutdown completed successfully");

    Ok(())
}
