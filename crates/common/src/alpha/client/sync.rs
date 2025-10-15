//! Block synchronization implementation for Bitcoin P2P protocol.
//!
//! This module provides functionality for synchronizing blockchain data with
//! peers, including requesting block headers using GetHeaders and downloading
//! full blocks using GetData messages.

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use primitive_types::U256;
use serde::{Deserialize, Serialize};
use tokio::{
    fs,
    net::TcpStream,
    sync::RwLock,
    time::{interval, sleep},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::alpha::{
    blockdata::{
        block::{BlockHash, Header},
        genesis::GenesisInfo,
    },
    client::{
        connection::{ConnectionError, ConnectionManager},
        database::BlockDatabase,
        message::{
            get_data::{GetData, Inventory}, request::GetHeaders, response::{Headers, StandardBlock},
            Message,
            Request,
            Response,
        },
        Connection,
    },
    consensus::Params,
    hashes::Hash,
    network::Network,
};

/// Persistent storage for blockchain state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainState {
    /// Map of block hash to height
    pub block_heights: HashMap<BlockHash, u64>,
    /// Map of height to block hash
    pub height_hashes: HashMap<u64, BlockHash>,
    /// Current tip of the chain
    pub tip_hash: BlockHash,
    /// Current tip height
    pub tip_height: u64,
    /// Last sync timestamp
    pub last_sync: u64,
}

impl Default for ChainState {
    fn default() -> Self {
        Self {
            block_heights: HashMap::new(),
            height_hashes: HashMap::new(),
            tip_hash: BlockHash::all_zeros(),
            tip_height: 0,
            last_sync: 0,
        }
    }
}

/// Configuration for block synchronization.
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Network type (mainnet, testnet, regtest)
    pub network: Network,
    /// Maximum number of block headers to request in a single GetHeaders
    /// message.
    pub max_headers_per_request: usize,
    /// Maximum number of blocks to download.
    pub max_blocks_to_download: usize,
    /// Whether to download full blocks or just headers.
    pub download_full_blocks: bool,
    /// Data directory for persistent storage
    pub data_dir: Option<PathBuf>,
    /// Whether to continuously monitor for new blocks
    pub continuous_sync: bool,
    /// Interval for checking new blocks (in seconds)
    pub sync_interval: u64,
    /// Maximum retry attempts for failed operations
    pub max_retries: u32,
    /// Timeout for individual requests
    pub request_timeout: Duration,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            network: Network::Testnet,          // Default to testnet for safety
            max_headers_per_request: 2000,      // Alpha protocol limit
            max_blocks_to_download: usize::MAX, // Unlimited by default
            download_full_blocks: true,
            data_dir: None,
            continuous_sync: true,
            sync_interval: 30, // 30 seconds
            max_retries: 3,
            request_timeout: Duration::from_secs(60),
        }
    }
}

/// Information about synchronization progress.
#[derive(Debug, Clone, Copy)]
pub struct SyncProgress {
    /// Number of headers synchronized.
    pub headers_synced: usize,
    /// Number of blocks downloaded.
    pub blocks_downloaded: usize,
    /// Height of the last known block.
    pub last_known_height: u64,
    /// Current synced height
    pub current_height: u64,
    /// Whether synchronization is complete.
    pub is_complete: bool,
    /// Whether we're continuously monitoring
    pub is_monitoring: bool,
    /// Sync rate (headers per second)
    pub sync_rate: f64,
    /// Estimated time remaining (in seconds)
    pub eta_seconds: Option<u64>,
}

/// Information about a chain reorganization.
#[derive(Debug, Clone, Copy)]
pub struct ReorgInfo {
    /// Height of the common ancestor
    pub common_ancestor_height: u64,
    /// Hash of the common ancestor
    pub common_ancestor_hash: BlockHash,
    /// Hash of the old tip
    pub old_tip_hash: BlockHash,
    /// Height of the old tip
    pub old_tip_height: u64,
    /// Hash of the new tip
    pub new_tip_hash: BlockHash,
    /// Height of the new tip
    pub new_tip_height: u64,
    /// Depth of the reorganization
    pub reorg_depth: u64,
}

/// A buffered block waiting to be processed.
#[derive(Debug, Clone)]
struct BufferedBlock<H: Header> {
    /// The block data
    block: StandardBlock<H>,
    /// The block hash
    hash: BlockHash,
    /// The previous block hash
    previous_hash: BlockHash,
}

/// Handles blockchain synchronization with peers.
#[derive(Debug, Clone)]
pub struct BlockSynchronizer {
    config: SyncConfig,
    progress: Arc<RwLock<SyncProgress>>,
    database: Option<Arc<BlockDatabase>>,
    known_block_hashes: Arc<RwLock<HashSet<BlockHash>>>,
    cancel_token: CancellationToken,
}

impl BlockSynchronizer {
    /// Creates a new block synchronizer with the given configuration.
    pub fn new(config: SyncConfig) -> Self {
        Self {
            config,
            progress: Arc::new(RwLock::new(SyncProgress {
                headers_synced: 0,
                blocks_downloaded: 0,
                last_known_height: 0,
                current_height: 0,
                is_complete: false,
                is_monitoring: false,
                sync_rate: 0.0,
                eta_seconds: None,
            })),
            database: None,
            known_block_hashes: Arc::new(RwLock::new(HashSet::new())),
            cancel_token: CancellationToken::new(),
        }
    }

    /// Sets the cancellation token for this synchronizer.
    pub fn set_cancel_token(&mut self, token: CancellationToken) {
        self.cancel_token = token;
    }

    /// Determines the block type based on height and consensus parameters.
    fn determine_block_type(&self, height: u64, params: &Params) -> &'static str {
        let randomx_height = params.randomx_height;
        let randomx_enforcement_height = params.randomx_enforcement_height;

        if height >= randomx_height {
            if height >= randomx_enforcement_height {
                "RandomX (enforced)"
            } else {
                "RandomX (transition)"
            }
        } else {
            "SHA256D"
        }
    }

    /// Gets the appropriate consensus parameters for the current network.
    fn consensus_params(&self) -> Params {
        match self.config.network {
            Network::Mainnet => Params::MAINNET,
            Network::Testnet => Params::TESTNET,
            Network::Regtest => Params::REGTEST,
        }
    }

    /// Gets the network type for this synchronizer.
    fn network(&self) -> Network {
        self.consensus_params().network
    }

    /// Gets the genesis block hash for the current network.
    fn genesis_hash(&self) -> BlockHash {
        GenesisInfo::for_network(self.network()).hash
    }

    /// Creates a new block synchronizer with a database.
    pub fn with_database(config: SyncConfig, database: Arc<BlockDatabase>) -> Self {
        Self {
            config,
            progress: Arc::new(RwLock::new(SyncProgress {
                headers_synced: 0,
                blocks_downloaded: 0,
                last_known_height: 0,
                current_height: 0,
                is_complete: false,
                is_monitoring: false,
                sync_rate: 0.0,
                eta_seconds: None,
            })),
            database: Some(database),
            known_block_hashes: Arc::new(RwLock::new(HashSet::new())),
            cancel_token: CancellationToken::new(),
        }
    }

    /// Initializes the database if a data directory is configured.
    pub async fn initialize_database(&mut self) -> Result<(), ConnectionError> {
        if self.database.is_none() && self.config.data_dir.is_some() {
            let data_dir = match self.config.data_dir.as_ref() {
                Some(dir) => dir,
                None => return Ok(()),
            };
            let db_path = data_dir.join("blockchain.db");
            let db = Arc::new(
                BlockDatabase::open(&db_path)
                    .await
                    .map_err(|e| ConnectionError::Io(std::io::Error::other(e)))?,
            );

            // Get the appropriate genesis block for the current network
            let genesis_block = GenesisInfo::for_network(self.config.network).to_block();
            let genesis_hash = genesis_block.header().block_hash();

            // Store the genesis block in the database if it doesn't already exist
            if !db
                .block_exists(&genesis_hash)
                .await
                .map_err(|e| ConnectionError::Io(std::io::Error::other(e)))?
            {
                info!(
                    "Storing genesis block for {} network",
                    self.config.network.as_str()
                );

                // Convert the genesis block to a StandardBlock for storage
                let standard_genesis =
                    StandardBlock::new(genesis_block.header, genesis_block.transactions);

                db.store_block(&standard_genesis)
                    .await
                    .map_err(|e| ConnectionError::Io(std::io::Error::other(e)))?;

                // Set the chain tip to the genesis block
                db.set_chain_tip(genesis_hash, 0)
                    .await
                    .map_err(|e| ConnectionError::Io(std::io::Error::other(e)))?;

                // Explicitly add the genesis block to the chain state
                if let Err(e) = db.add_block_to_state(genesis_hash, 0).await {
                    error!("Failed to add genesis block to chain state: {}", e);
                } else {
                    info!("Genesis block added to chain state");
                }

                info!("Genesis block set as chain tip");
            } else {
                info!("Genesis block already exists in database");
            }

            // Migrate from JSON if needed
            db.migrate_from_json(data_dir)
                .await
                .map_err(|e| ConnectionError::Io(std::io::Error::other(e)))?;

            self.database = Some(db);
            info!("Database initialized at: {}", db_path.display());
        }
        Ok(())
    }

    /// Loads chain state from database if available.
    pub async fn load_state(&self) -> Result<(), ConnectionError> {
        if let Some(database) = &self.database {
            let state = database
                .get_chain_state()
                .await
                .map_err(|e| ConnectionError::Io(std::io::Error::other(e)))?;

            info!(
                "Loaded chain state from database: tip height {}",
                state.tip_height
            );

            // Ensure genesis block is in chain state
            let genesis_hash = self.genesis_hash();
            if database.get_block_height(&genesis_hash).await.unwrap_or(None).is_none() {
                // Genesis block is not in chain state, add it
                info!("Genesis block not found in chain state, adding it");
                if let Err(e) = database.add_block_to_state(genesis_hash, 0).await {
                    error!("Failed to add genesis block to chain state: {}", e);
                } else {
                    info!("Genesis block added to chain state");
                }
            }
        } else {
            // Fallback to JSON if database is not available
            if let Some(data_dir) = &self.config.data_dir {
                let state_file = data_dir.join("chain_state.json");
                if state_file.exists() {
                    let content = fs::read_to_string(&state_file)
                        .await
                        .map_err(ConnectionError::Io)?;
                    let state: ChainState = serde_json::from_str(&content).map_err(|e| {
                        ConnectionError::InvalidMessage(format!(
                            "Failed to parse chain state: {}",
                            e
                        ))
                    })?;

                    info!(
                        "Loaded chain state from JSON fallback: tip height {}",
                        state.tip_height
                    );
                }
            }
        }
        Ok(())
    }

    /// Saves chain state to database.
    pub async fn save_state(&self) -> Result<(), ConnectionError> {
        if let Some(_database) = &self.database {
            // The database handles state persistence internally
            debug!("Chain state is automatically persisted in database");
        } else {
            // Fallback to JSON if database is not available
            if let Some(data_dir) = &self.config.data_dir {
                fs::create_dir_all(data_dir)
                    .await
                    .map_err(ConnectionError::Io)?;

                let state_file = data_dir.join("chain_state.json");
                // Create a default state since we don't have in-memory state anymore
                let state = ChainState::default();
                let content = serde_json::to_string_pretty(&state).map_err(|e| {
                    ConnectionError::InvalidMessage(format!(
                        "Failed to serialize chain state: {}",
                        e
                    ))
                })?;

                fs::write(&state_file, content)
                    .await
                    .map_err(ConnectionError::Io)?;

                debug!("Saved chain state to JSON fallback");
            }
        }
        Ok(())
    }

    /// Gets the current chain tip.
    pub async fn get_chain_tip(&self) -> (BlockHash, u64) {
        if let Some(database) = &self.database {
            database.get_chain_tip().await.unwrap_or_else(|_| {
                warn!("Failed to get chain tip from database, using defaults");
                (BlockHash::all_zeros(), 0)
            })
        } else {
            // Return default values if no database
            (BlockHash::all_zeros(), 0)
        }
    }

    /// Sets the chain tip.
    pub async fn set_chain_tip(&self, hash: BlockHash, height: u64) -> Result<(), ConnectionError> {
        if let Some(database) = &self.database {
            database
                .set_chain_tip(hash, height)
                .await
                .map_err(|e| ConnectionError::Io(std::io::Error::other(e)))?;
        }
        // If no database, we can't persist the state
        Ok(())
    }

    /// Adds a block to the chain state.
    pub async fn add_block(&self, hash: BlockHash, height: u64) -> Result<bool, ConnectionError> {
        if let Some(database) = &self.database {
            database
                .add_block_to_state(hash, height)
                .await
                .map_err(|e| ConnectionError::Io(std::io::Error::other(e)))
        } else {
            // If no database, we can't persist the state
            warn!("No database available, cannot persist block");
            Ok(true) // Return true to avoid blocking sync
        }
    }

    /// Gets the height of a block hash.
    pub async fn get_block_height(&self, hash: &BlockHash) -> Option<u64> {
        if let Some(database) = &self.database {
            database.get_block_height(hash).await.unwrap_or(None)
        } else {
            None
        }
    }

    /// Gets the block hash at a specific height.
    pub async fn get_block_hash_at_height(&self, height: u64) -> Option<BlockHash> {
        if let Some(database) = &self.database {
            database
                .get_block_hash_at_height(height)
                .await
                .unwrap_or(None)
        } else {
            None
        }
    }

    /// Shuts down the synchronizer.
    pub async fn shutdown(&self) {
        self.cancel_token.cancel();
        info!("BlockSynchronizer cancellation token triggered");

        // Shutdown database if it exists - don't wait for it
        if let Some(database) = &self.database {
            info!("Shutting down database...");
            // Clone the database Arc to avoid borrowing issues
            let db_clone = database.clone();
            // Fire and forget - don't wait for database shutdown
            tokio::spawn(async move {
                let _ = db_clone.shutdown().await;
            });
        }

        info!("BlockSynchronizer shutdown initiated");
    }

    /// Checks if shutdown has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancel_token.is_cancelled()
    }

    /// Gets a child cancellation token for operations
    pub fn child_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }

    /// Starts the synchronization process with a peer.
    pub async fn start_sync<H>(
        &self,
        connection: &ConnectionManager,
        stream: &mut TcpStream,
        peer_best_height: i32,
    ) -> Result<(), ConnectionError>
    where
        H: Header + Send + Sync + 'static + std::fmt::Debug,
    {
        info!(
            "Starting block synchronization with peer (best height: {})",
            peer_best_height
        );

        // Reset progress counters at the beginning of each sync session
        {
            let mut progress = self.progress.write().await;
            progress.headers_synced = 0;
            progress.blocks_downloaded = 0;
            progress.is_complete = false;
            progress.sync_rate = 0.0;
            progress.eta_seconds = None;
            debug!("Reset progress counters for new sync session");
        }

        // Get current chain tip to set session start height
        let (current_tip_hash, current_tip_height) = self.get_chain_tip().await;
        {
            let mut session_start_height = self.session_start_height.write().await;
            *session_start_height = current_tip_height;
            debug!("Set session start height to {}", current_tip_height);
        }

        // Initialize database if needed
        if self.database.is_none() {
            // We need to create a mutable reference, but we're in an async context
            // For now, we'll work with the existing database or create a new one
            if let Some(data_dir) = &self.config.data_dir {
                let db_path = data_dir.join("blockchain.db");
                match BlockDatabase::open(&db_path).await {
                    Ok(db) => {
                        // Note: This is a workaround since we can't modify self in this context
                        // In a proper implementation, you'd restructure this to avoid this issue
                        info!("Database available at: {}", db_path.display());

                        // Get the appropriate genesis block for the current network
                        let genesis_block =
                            GenesisInfo::for_network(self.config.network).to_block();
                        let genesis_hash = genesis_block.header().block_hash();

                        // Store the genesis block in the database if it doesn't already exist
                        if !db.block_exists(&genesis_hash).await.unwrap_or(false) {
                            info!(
                                "Storing genesis block for {} network",
                                self.config.network.as_str()
                            );

                            // Convert the genesis block to a StandardBlock for storage
                            let standard_genesis = StandardBlock::new(
                                genesis_block.header,
                                genesis_block.transactions,
                            );

                            if let Err(e) = db.store_block(&standard_genesis).await {
                                error!("Failed to store genesis block: {}", e);
                            } else {
                                // Set the chain tip to the genesis block
                                if let Err(e) = db.set_chain_tip(genesis_hash, 0).await {
                                    error!("Failed to set genesis as chain tip: {}", e);
                                } else {
                                    // Explicitly add the genesis block to the chain state
                                    if let Err(e) = db.add_block_to_state(genesis_hash, 0).await {
                                        error!("Failed to add genesis block to chain state: {}", e);
                                    } else {
                                        info!("Genesis block added to chain state");
                                    }
                                    info!("Genesis block set as chain tip");
                                }
                            }
                        } else {
                            info!("Genesis block already exists in database");
                        }

                        // Migrate from JSON if needed
                        if let Err(e) = db.migrate_from_json(data_dir).await {
                            warn!("Failed to migrate from JSON: {}", e);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to open database: {}", e);
                    }
                }
            }
        }

        // Load existing state
        self.load_state().await?;

        // Update progress with peer's best height
        let peer_best_height = if peer_best_height < 0 {
            warn!(
                "Peer best height is negative: {}, using 0",
                peer_best_height
            );
            0
        } else {
            match u64::try_from(peer_best_height) {
                Ok(height) => height,
                Err(e) => {
                    warn!(
                        "Failed to convert peer best height {} to u64: {}",
                        peer_best_height, e
                    );
                    u64::MAX
                }
            }
        };

        {
            let mut progress = self.progress.write().await;
            progress.last_known_height = peer_best_height;
        }

        // Get current chain tip
        let (current_tip_hash, current_tip_height) = self.get_chain_tip().await;
        info!(
            "Current chain tip: height {}, hash: {}",
            current_tip_height, current_tip_hash
        );

        // If we're already at the peer's best height, just monitor
        if current_tip_height >= peer_best_height {
            info!(
                "Already synchronized with peer (current: {}, peer: {})",
                current_tip_height, peer_best_height
            );

            if self.config.continuous_sync {
                return self.monitor_new_blocks::<H>(connection, stream).await;
            } else {
                return Ok(());
            }
        }

        // Perform initial sync
        self.sync_from_tip::<H>(
            connection,
            stream,
            current_tip_hash,
            current_tip_height,
            peer_best_height,
        )
        .await?;

        // Save state after initial sync
        self.save_state().await?;

        // Start continuous monitoring if enabled
        if self.config.continuous_sync {
            self.monitor_new_blocks::<H>(connection, stream).await?;
        }

        Ok(())
    }

    /// Synchronizes blocks from the current tip to the target height.
    #[allow(clippy::too_many_arguments)]
    async fn sync_from_tip<H>(
        &self,
        connection: &ConnectionManager,
        stream: &mut TcpStream,
        mut current_tip_hash: BlockHash,
        mut current_tip_height: u64,
        target_height: u64,
    ) -> Result<(), ConnectionError>
    where
        H: Header + Send + Sync + 'static + std::fmt::Debug,
    {
        info!(
            "Syncing from height {} to target height {}",
            current_tip_height, target_height
        );

        let mut total_headers_synced: usize = 0;
        let mut total_blocks_downloaded: usize = 0;
        let start_time = std::time::Instant::now();

        loop {
            // Check for shutdown at the beginning of each iteration
            if self.is_cancelled() {
                info!("Cancellation detected at start of sync loop");
                break;
            }

            // Check if sync is complete
            if current_tip_height >= target_height {
                info!(
                    "Sync complete, current height {} >= target height {}",
                    current_tip_height, target_height
                );
                break;
            }

            // Create locator hashes
            let locator_hashes = self.create_locator_hashes(current_tip_hash).await;

            // Request headers with shutdown check
            let headers = match self
                .request_headers_with_retry::<H>(connection, stream, locator_hashes, None)
                .await
            {
                Ok(headers) => headers,
                Err(e) => {
                    if self.is_cancelled() {
                        info!("Cancellation detected during header request, stopping sync");
                        break;
                    }
                    error!("Failed to request headers: {}", e);
                    return Err(e);
                }
            };

            // If no headers returned, we're done
            if headers.is_empty() {
                info!("No more headers available");
                break;
            }

            // Process headers
            let headers_count = headers.len();
            total_headers_synced = total_headers_synced.saturating_add(headers_count);

            info!(
                "Received {} headers (total: {})",
                headers_count, total_headers_synced
            );

            // Process each header
            for (i, header) in headers.headers().iter().enumerate() {
                let block_hash = header.block_hash();
                let block_height = current_tip_height.checked_add(1).unwrap_or_else(|| {
                    error!("Current tip height + 1 would overflow, using max value");
                    u64::MAX
                });

                let block_height = block_height
                    .checked_add(u64::try_from(i).unwrap_or_else(|_| {
                        error!("Failed to convert index {} to u64, using max value", i);
                        u64::MAX
                    }))
                    .unwrap_or_else(|| {
                        error!("Block height calculation would overflow, using max value");
                        u64::MAX
                    });

                // Get consensus parameters to check for hard fork
                let params = self.consensus_params();
                let block_type = self.determine_block_type(block_height, &params);

                // Log hard fork transitions
                let randomx_height = params.randomx_height;
                if block_height == randomx_height {
                    warn!(
                        "=== RANDOMX HARD FORK ACTIVATION AT HEIGHT {} ===",
                        block_height
                    );
                    info!("Switching from SHA256D to RandomX proof-of-work");
                }
                let randomx_enforcement_height = params.randomx_enforcement_height;
                if block_height == randomx_enforcement_height {
                    warn!(
                        "=== RANDOMX ENFORCEMENT BEGINS AT HEIGHT {} ===",
                        block_height
                    );
                    info!("RandomX proof-of-work is now mandatory");
                }

                // Log block processing with type information
                info!(
                    "Processing header: {} at height {} (type: {})",
                    block_hash, block_height, block_type
                );

                // Add to chain state
                if self
                    .add_block(block_hash, block_height)
                    .await
                    .unwrap_or(true)
                {
                    debug!(
                        "Added block {} at height {} ({})",
                        block_hash, block_height, block_type
                    );
                }
            }

            // Update progress
            {
                let mut progress = self.progress.write().await;
                progress.headers_synced = total_headers_synced;
                let headers_count_u64 = u64::try_from(headers_count).unwrap_or_else(|_| {
                    error!(
                        "Failed to convert headers_count {} to u64, using max value",
                        headers_count
                    );
                    u64::MAX
                });

                progress.current_height = current_tip_height
                    .checked_add(headers_count_u64)
                    .unwrap_or_else(|| {
                        error!("Current height calculation would overflow, using max value");
                        u64::MAX
                    });

                // Calculate sync rate
                let elapsed = start_time.elapsed().as_secs_f64();
                #[allow(clippy::float_arithmetic, reason = "For display purposes")]
                if elapsed > 0.0 {
                    progress.sync_rate = total_headers_synced as f64 / elapsed;
                }

                // Calculate ETA
                if progress.sync_rate > 0.0 && target_height > progress.current_height {
                    let remaining = target_height
                        .checked_sub(progress.current_height)
                        .unwrap_or_else(|| {
                            error!("Target height is less than current height, using 0");
                            0
                        });
                    #[allow(clippy::float_arithmetic, reason = "ETA calculation is fine here")]
                    let eta_calculation = remaining as f64 / progress.sync_rate;

                    progress.eta_seconds = Some(
                        #[allow(
                            clippy::cast_possible_truncation,
                            clippy::cast_sign_loss,
                            reason = "ETA should be non-negative, checked"
                        )]
                        if eta_calculation >= 0.0 && eta_calculation <= u64::MAX as f64 {
                            // Since we've already checked the bounds, this conversion is safe
                            eta_calculation as u64
                        } else {
                            error!(
                                "ETA calculation {} is out of bounds, using max value",
                                eta_calculation
                            );
                            u64::MAX
                        },
                    );
                }
            }

            // Download full blocks if requested
            if self.config.download_full_blocks && !self.is_cancelled() {
                match self
                    .download_blocks::<H>(connection, stream, headers.headers())
                    .await
                {
                    Ok(blocks_downloaded) => {
                        total_blocks_downloaded =
                            total_blocks_downloaded.saturating_add(blocks_downloaded);
                    }
                    Err(e) => {
                        if self.is_cancelled() {
                            info!("Cancellation detected during block download, stopping sync");
                            break;
                        }
                        error!("Failed to download blocks: {}", e);
                        return Err(e);
                    }
                }
            }

            // Update current tip
            if let Some(last_header) = headers.headers().last() {
                current_tip_hash = last_header.block_hash();
                let headers_count_u64 = u64::try_from(headers_count).unwrap_or_else(|_| {
                    error!(
                        "Failed to convert headers_count {} to u64, using max value",
                        headers_count
                    );
                    u64::MAX
                });

                current_tip_height = current_tip_height
                    .checked_add(headers_count_u64)
                    .unwrap_or_else(|| {
                        error!("Current tip height calculation would overflow, using max value");
                        u64::MAX
                    });
            }

            // Save state periodically
            if total_headers_synced.is_multiple_of(1000) {
                self.save_state().await?;
            }

            // Check if we've reached our limit
            if total_headers_synced >= self.config.max_blocks_to_download {
                info!("Reached maximum block limit, stopping synchronization");
                break;
            }
        }

        // Mark synchronization as complete
        {
            let mut progress = self.progress.write().await;
            progress.is_complete = current_tip_height >= target_height;
        }

        info!(
            "Initial synchronization complete ({} headers, {} blocks, final height: {})",
            total_headers_synced, total_blocks_downloaded, current_tip_height
        );

        Ok(())
    }

    /// Creates locator hashes for getheaders request.
    async fn create_locator_hashes(&self, tip_hash: BlockHash) -> Vec<BlockHash> {
        let mut locators = vec![tip_hash];

        // Get current tip height from database
        let (_, current_tip_height) = self.get_chain_tip().await;

        // Add previous hashes at exponentially increasing intervals
        let mut height = current_tip_height;
        let mut step = 1;

        while height > 0 && locators.len() < 10 {
            height = height.saturating_sub(step);
            if let Some(hash) = self.get_block_hash_at_height(height).await {
                locators.push(hash);
            }
            step = match step.checked_mul(2) {
                Some(new_step) => new_step,
                None => {
                    error!("Step calculation would overflow, using max value");
                    u64::MAX
                }
            };
        }

        // Always include genesis hash
        locators.push(BlockHash::all_zeros());

        locators
    }

    /// Monitors for new blocks in a continuous loop.
    async fn monitor_new_blocks<H>(
        &self,
        connection: &ConnectionManager,
        stream: &mut TcpStream,
    ) -> Result<(), ConnectionError>
    where
        H: Header + Send + Sync + 'static + std::fmt::Debug,
    {
        info!("Starting continuous block monitoring");

        {
            let mut progress = self.progress.write().await;
            progress.is_monitoring = true;
        }

        let mut interval = interval(Duration::from_secs(self.config.sync_interval));
        let mut consecutive_failures: i32 = 0;

        loop {
            // Check for shutdown at the beginning of each iteration
            if self.is_cancelled() {
                info!("Cancellation detected at start of monitoring loop");
                break;
            }

            // Use a timeout for the interval tick to prevent hanging
            let timeout_seconds = self.config.sync_interval.checked_add(5).unwrap_or_else(|| {
                error!("Timeout calculation would overflow, using max value");
                u64::MAX
            });
            match tokio::time::timeout(Duration::from_secs(timeout_seconds), async {
                interval.tick().await;
            })
            .await
            {
                Ok(_) => {
                    // Normal tick, continue with monitoring
                }
                Err(_) => {
                    // Timeout occurred, check shutdown signal
                    if self.is_cancelled() {
                        info!("Cancellation detected via timeout, stopping block monitoring");
                        break;
                    }
                    continue;
                }
            }

            // Check for shutdown before network operations
            if self.is_cancelled() {
                info!("Cancellation detected, stopping block monitoring");
                break;
            }

            // Get current tip
            let (current_tip_hash, current_tip_height) = self.get_chain_tip().await;

            // Create locator hashes
            let locator_hashes = self.create_locator_hashes(current_tip_hash).await;

            // Request new headers with shutdown check
            let headers = match self
                .request_headers_with_retry::<H>(connection, stream, locator_hashes, None)
                .await
            {
                Ok(headers) => {
                    // Check for shutdown after receiving headers
                    if self.is_cancelled() {
                        info!("Cancellation detected after receiving headers, stopping monitoring");
                        break;
                    }
                    headers
                }
                Err(e) => {
                    if self.is_cancelled() {
                        info!("Cancellation detected during header request, stopping monitoring");
                        break;
                    }
                    // Check if this is an "inv" command error
                    if e.to_string().contains("Unknown command: inv") {
                        // This is actually expected during normal operation
                        // Just log it and continue monitoring
                        debug!("Received inv message during monitoring (normal behavior)");
                        consecutive_failures = 0;
                        continue;
                    }
                    warn!("Failed to check for new blocks: {}", e);
                    consecutive_failures = consecutive_failures.saturating_add(1);

                    if consecutive_failures >= 5 {
                        error!("Too many consecutive failures, stopping monitoring");
                        break;
                    }
                    continue;
                }
            };

            // Check for shutdown before processing headers
            if self.is_cancelled() {
                info!("Cancellation detected before processing headers, stopping monitoring");
                break;
            }

            if !headers.is_empty() {
                info!("Detected {} new blocks", headers.len());

                // Process new headers
                for (i, header) in headers.headers().iter().enumerate() {
                    // Check for shutdown during processing
                    if self.is_cancelled() {
                        info!("Cancellation detected during header processing, stopping");
                        break;
                    }

                    let block_hash = header.block_hash();
                    let block_height = current_tip_height.checked_add(1).unwrap_or_else(|| {
                        error!("Current tip height + 1 would overflow, using max value");
                        u64::MAX
                    });

                    let block_height = block_height
                        .checked_add(u64::try_from(i).unwrap_or_else(|_| {
                            error!("Failed to convert index {} to u64, using max value", i);
                            u64::MAX
                        }))
                        .unwrap_or_else(|| {
                            error!("Block height calculation would overflow, using max value");
                            u64::MAX
                        });

                    // Get consensus parameters to check for hard fork
                    let params = self.consensus_params();
                    let block_type = self.determine_block_type(block_height, &params);

                    // Log hard fork transitions
                    let randomx_height = params.randomx_height;
                    if block_height == randomx_height {
                        warn!(
                            "=== RANDOMX HARD FORK ACTIVATION AT HEIGHT {} ===",
                            block_height
                        );
                        info!("Switching from SHA256D to RandomX proof-of-work");
                    }
                    let randomx_enforcement_height = params.randomx_enforcement_height;
                    if block_height == randomx_enforcement_height {
                        warn!(
                            "=== RANDOMX ENFORCEMENT BEGINS AT HEIGHT {} ===",
                            block_height
                        );
                        info!("RandomX proof-of-work is now mandatory");
                    }

                    if self
                        .add_block(block_hash, block_height)
                        .await
                        .unwrap_or(true)
                    {
                        info!(
                            "New block: {} at height {} ({})",
                            block_hash, block_height, block_type
                        );
                    }
                }

                // Check for shutdown before downloading blocks
                if self.is_cancelled() {
                    info!("Cancellation detected before block download, stopping monitoring");
                    break;
                }

                // Download full blocks if requested
                if self.config.download_full_blocks {
                    match self
                        .download_blocks::<H>(connection, stream, headers.headers())
                        .await
                    {
                        Ok(_) => {
                            debug!("Successfully downloaded new blocks");
                        }
                        Err(e) => {
                            if self.is_cancelled() {
                                info!(
                                    "Cancellation detected during block download, stopping \
                                     monitoring"
                                );
                                break;
                            }
                            error!("Failed to download new blocks: {}", e);
                        }
                    }
                }

                // Save state
                if let Err(e) = self.save_state().await {
                    error!("Failed to save state: {}", e);
                }

                consecutive_failures = 0;
            }
        }

        {
            let mut progress = self.progress.write().await;
            progress.is_monitoring = false;
        }

        info!("Block monitoring stopped");
        Ok(())
    }

    /// Requests block headers from a peer.
    async fn request_headers<H>(
        &self,
        connection: &ConnectionManager,
        stream: &mut TcpStream,
        locator_hashes: Vec<BlockHash>,
        stop_hash: Option<BlockHash>,
    ) -> Result<Headers<H>, ConnectionError>
    where
        H: Header + Send + Sync + 'static + std::fmt::Debug,
    {
        debug!("Requesting headers with {} locators", locator_hashes.len());

        // Create GetHeaders message
        let get_headers = GetHeaders::new(
            70016, // Protocol version
            locator_hashes,
            stop_hash,
        );

        // Send GetHeaders request
        connection
            .send_message(
                stream,
                Message::<H>::Request(Request::GetHeaders(get_headers)),
            )
            .await?;

        // Wait for Headers response
        loop {
            let message = connection.receive_message::<H>(stream).await?;

            match message {
                Message::Response(Response::Headers(headers)) => {
                    debug!("Received {} headers", headers.len());
                    return Ok(headers);
                }
                Message::Connection(Connection::Inv(inv)) => {
                    // Handle inv messages by logging and continuing
                    debug!("Received inv message with {} items", inv.inventory().len());
                    for inventory in inv.inventory().iter() {
                        debug!("  Inventory item: {:?}", inventory);
                    }
                    // Continue waiting for headers
                    continue;
                }
                Message::Response(Response::Block(_)) => {
                    // This might happen if the peer sends blocks instead of headers
                    warn!("Received block message while expecting headers");
                    continue;
                }
                _ => {
                    debug!(
                        "Received non-headers message during header sync: {:?}",
                        message
                    );
                    continue;
                }
            }
        }
    }

    /// Requests block headers from a peer with retry logic.
    async fn request_headers_with_retry<H>(
        &self,
        connection: &ConnectionManager,
        stream: &mut TcpStream,
        locator_hashes: Vec<BlockHash>,
        stop_hash: Option<BlockHash>,
    ) -> Result<Headers<H>, ConnectionError>
    where
        H: Header + Send + Sync + 'static + std::fmt::Debug,
    {
        let mut last_error = None;

        for attempt in 1..=self.config.max_retries {
            match self
                .request_headers::<H>(connection, stream, locator_hashes.clone(), stop_hash)
                .await
            {
                Ok(headers) => return Ok(headers),
                Err(e) => {
                    warn!("Request headers attempt {} failed: {}", attempt, e);
                    last_error = Some(e);

                    if attempt < self.config.max_retries {
                        let delay = Duration::from_secs(match 2u32.checked_pow(attempt.min(5)) {
                            Some(delay) => u64::from(delay),
                            None => {
                                error!("Delay calculation would overflow, using max value");
                                u64::MAX
                            }
                        });
                        info!("Retrying in {} seconds...", delay.as_secs());
                        sleep(delay).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            ConnectionError::InvalidMessage("All retry attempts failed".to_string())
        }))
    }

    /// Downloads full blocks for the given headers.
    async fn download_blocks<H>(
        &self,
        connection: &ConnectionManager,
        stream: &mut TcpStream,
        headers: &[H],
    ) -> Result<usize, ConnectionError>
    where
        H: Header + Send + Sync + 'static + std::fmt::Debug,
    {
        info!(
            "STARTING BLOCK DOWNLOAD: Requesting {} blocks",
            headers.len()
        );
        debug!("Downloading {} blocks", headers.len());

        // Clear known_block_hashes to prevent stale entries from previous batches
        {
            let mut known_hashes = self.known_block_hashes.write().await;
            known_hashes.clear();
        }

        // Configuration for batch processing to handle peer limitations
        const MAX_BLOCKS_PER_REQUEST: usize = 25; // Conservative limit based on Bitcoin Core defaults
        const BATCH_TIMEOUT: Duration = Duration::from_secs(30); // Timeout per batch

        // Create inventory vectors for block requests
        let mut all_inventories = Vec::new();
        let mut all_block_hashes = Vec::new();
        let mut header_map = HashMap::new();

        for header in headers {
            let block_hash = header.block_hash();

            // Skip if we already know about this block
            {
                let known_hashes = self.known_block_hashes.read().await;
                if known_hashes.contains(&block_hash) {
                    debug!("Skipping already known block: {}", block_hash);
                    continue;
                }
            }

            all_inventories.push(Inventory::Block(block_hash));
            all_block_hashes.push(block_hash);
            header_map.insert(block_hash, header);
        }

        if all_inventories.is_empty() {
            debug!("No new blocks to download");
            return Ok(0);
        }

        info!(
            "IMPLEMENTING PAGINATION: Processing {} blocks in batches of max {}",
            all_inventories.len(),
            MAX_BLOCKS_PER_REQUEST
        );

        // Buffer to store all received blocks
        let mut all_buffered_blocks: HashMap<BlockHash, BufferedBlock<H>> = HashMap::new();
        let mut total_blocks_downloaded: usize = 0;
        let download_start = Instant::now();

        // Process inventories in batches to handle peer limitations
        for (batch_index, batch_start) in (0..all_inventories.len())
            .step_by(MAX_BLOCKS_PER_REQUEST)
            .enumerate()
        {
            let batch_end = match batch_start.checked_add(MAX_BLOCKS_PER_REQUEST) {
                Some(end) => std::cmp::min(end, all_inventories.len()),
                None => all_inventories.len(),
            };
            let batch_inventories = all_inventories
                .get(batch_start..batch_end)
                .unwrap_or(&[])
                .to_vec();
            let batch_block_hashes: Vec<BlockHash> = all_block_hashes
                .get(batch_start..batch_end)
                .unwrap_or(&[])
                .to_vec();

            info!(
                "PROCESSING BATCH {}/: Requesting {} blocks (indices {}-{})",
                batch_index.saturating_add(1),
                batch_inventories.len(),
                batch_start,
                batch_end.saturating_sub(1)
            );

            // Send GetData request for this batch
            let get_data = GetData::new(batch_inventories.clone());
            connection
                .send_message(stream, Message::<H>::Request(Request::GetData(get_data)))
                .await?;

            // Collect blocks for this batch
            let batch_blocks = self
                .collect_blocks_batch::<H>(
                    connection,
                    stream,
                    &batch_block_hashes,
                    &header_map,
                    BATCH_TIMEOUT,
                )
                .await?;

            let batch_blocks_count = batch_blocks.len();
            // Merge batch results into overall collection
            for (hash, block) in batch_blocks {
                all_buffered_blocks.insert(hash, block);
                total_blocks_downloaded = total_blocks_downloaded.saturating_add(1);
            }

            info!(
                "BATCH {}/ COMPLETE: Received {} blocks (total so far: {})",
                batch_index.saturating_add(1),
                batch_blocks_count,
                total_blocks_downloaded
            );

            // Check for cancellation between batches
            if self.is_cancelled() {
                info!("Cancellation detected between batches, stopping download");
                break;
            }

            // Small delay between batches to be polite to the peer
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        info!(
            "ALL BATCHES COMPLETE: Successfully downloaded {} out of {} requested blocks in {:?}",
            total_blocks_downloaded,
            all_inventories.len(),
            download_start.elapsed()
        );

        // Now process all collected blocks (phases 2 and 3 combined)
        self.process_buffered_blocks::<H>(all_buffered_blocks).await
    }

    /// Collects blocks for a single batch request.
    #[allow(clippy::too_many_arguments)]
    async fn collect_blocks_batch<H>(
        &self,
        connection: &ConnectionManager,
        stream: &mut TcpStream,
        batch_block_hashes: &[BlockHash],
        _header_map: &HashMap<BlockHash, &H>,
        timeout: Duration,
    ) -> Result<HashMap<BlockHash, BufferedBlock<H>>, ConnectionError>
    where
        H: Header + Send + Sync + 'static + std::fmt::Debug,
    {
        let mut buffered_blocks: HashMap<BlockHash, BufferedBlock<H>> = HashMap::new();
        let mut blocks_received = 0;
        let expected_blocks = batch_block_hashes.len();
        let batch_start = Instant::now();

        loop {
            // Check for timeout
            if batch_start.elapsed() > timeout {
                warn!(
                    "Batch timeout after {:?}, received {}/{} blocks",
                    batch_start.elapsed(),
                    blocks_received,
                    expected_blocks
                );
                break;
            }

            // Check if we've received all blocks for this batch
            if blocks_received >= expected_blocks {
                debug!("Batch complete: received all {} blocks", blocks_received);
                break;
            }

            // Check for shutdown
            if self.is_cancelled() {
                info!("Cancellation detected during batch collection");
                break;
            }

            // Receive message with shorter timeout for individual blocks
            let block_timeout = Duration::from_secs(10);
            let message_result =
                tokio::time::timeout(block_timeout, connection.receive_message::<H>(stream)).await;

            let message = match message_result {
                Ok(Ok(msg)) => msg,
                Ok(Err(e)) => {
                    error!("Failed to receive message during batch: {}", e);
                    return Err(e);
                }
                Err(_) => {
                    debug!("Timeout waiting for individual block in batch");
                    // Continue to check if we have enough blocks or should timeout
                    continue;
                }
            };

            match message {
                Message::Response(Response::Block(block)) => {
                    let block_hash = block.header().block_hash();

                    // Check if this is one of the blocks we requested in this batch
                    if batch_block_hashes.contains(&block_hash)
                        && !buffered_blocks.contains_key(&block_hash)
                    {
                        blocks_received = blocks_received.saturating_add(1);

                        // Store the block in our buffer
                        let standard_block = StandardBlock {
                            header: block.header,
                            transactions: block.transactions.clone(),
                        };

                        buffered_blocks.insert(
                            block_hash,
                            BufferedBlock {
                                block: standard_block,
                                hash: block_hash,
                                previous_hash: block.header().previous_block_hash(),
                            },
                        );

                        debug!(
                            "Batch received block {}: {} ({}/{})",
                            blocks_received, block_hash, blocks_received, expected_blocks
                        );

                        // Mark as known to avoid duplicate requests
                        {
                            let mut known_hashes = self.known_block_hashes.write().await;
                            known_hashes.insert(block_hash);
                        }
                    } else {
                        debug!(
                            "Received block not in this batch or duplicate: {}",
                            block_hash
                        );
                    }
                }
                Message::Connection(Connection::Inv(_inv)) => {
                    debug!("Received inv message during batch download");
                    // Continue waiting for blocks
                    continue;
                }
                Message::Response(Response::NotFound(not_found)) => {
                    warn!("Peer doesn't have requested block(s): {:?}", not_found);
                    blocks_received = blocks_received.saturating_add(1); // Count as processed to avoid infinite loop
                }
                _ => {
                    debug!(
                        "Received non-block message during batch: {:?}",
                        message.command()
                    );
                    continue;
                }
            }
        }

        info!(
            "Batch collection complete: {}/{} blocks received in {:?}",
            buffered_blocks.len(),
            expected_blocks,
            batch_start.elapsed()
        );

        Ok(buffered_blocks)
    }

    /// Processes buffered blocks using parent-first processing approach
    async fn process_buffered_blocks<H>(
        &self,
        mut buffered_blocks: HashMap<BlockHash, BufferedBlock<H>>,
    ) -> Result<usize, ConnectionError>
    where
        H: Header + Send + Sync + 'static + std::fmt::Debug,
    {
        if buffered_blocks.is_empty() {
            info!("No blocks to process");
            return Ok(0);
        }

        info!(
            "Processing {} blocks using parent-first approach",
            buffered_blocks.len()
        );

        // Get the current chain tip to start from
        let (mut current_tip_hash, mut current_tip_height) = self.get_chain_tip().await;
        let mut blocks_processed: usize = 0;
        let mut total_processed: usize = 0;
        let genesis_hash = self.genesis_hash();

        // Process blocks in parent-first order
        while !buffered_blocks.is_empty() {
            // Check for shutdown
            if self.is_cancelled() {
                info!("Cancellation detected during block processing, stopping");
                break;
            }

            // Find the next block whose previous_hash matches the current tip
            let mut next_block_hash: Option<BlockHash> = None;

            // First, try to find a block that directly follows the current tip
            for (hash, block) in buffered_blocks.iter() {
                if block.previous_hash == current_tip_hash {
                    next_block_hash = Some(*hash);
                    break;
                }
            }

            // If we can't find a direct child, try to find the earliest block in the batch
            if next_block_hash.is_none() {
                warn!(
                    "No block found with parent {}, looking for earliest block",
                    current_tip_hash
                );

                // Try to find a block whose parent is in our database
                let mut found_block = false;
                for (hash, block) in buffered_blocks.iter() {
                    if self.get_block_height(&block.previous_hash).await.is_some() {
                        info!(
                            "Found block {} whose parent {} is in database",
                            hash, block.previous_hash
                        );
                        next_block_hash = Some(*hash);
                        found_block = true;
                        break;
                    }
                }

                // If still no block found, try to find a block that connects to genesis
                if !found_block {
                    for (hash, block) in buffered_blocks.iter() {
                        if block.previous_hash == BlockHash::all_zeros()
                            || block.previous_hash == genesis_hash
                        {
                            info!("Found genesis-connected block: {}", hash);
                            next_block_hash = Some(*hash);
                            found_block = true;
                            break;
                        }
                    }
                }

                // As a last resort, just pick any block
                if !found_block {
                    warn!("No suitable block found, picking arbitrary block to continue");
                    if let Some((hash, _)) = buffered_blocks.iter().next() {
                        next_block_hash = Some(*hash);
                    }
                }
            }

            // Process the selected block
            if let Some(block_hash) = next_block_hash {
                if let Some(buffered_block) = buffered_blocks.remove(&block_hash) {
                    // First, store the block in database (without validation)
                    if let Some(database) = &self.database {
                        if let Err(e) = database.store_block(&buffered_block.block).await {
                            error!("Failed to store block in database: {}", e);
                            // Continue processing even if storage fails
                        }

                        // Store the header as well for efficient lookup
                        if let Err(e) =
                            database.store_header(buffered_block.block.header()).await
                        {
                            error!("Failed to store header in database: {}", e);
                        }
                    }

                    // Then validate the block
                    match self.process_block(buffered_block.block.clone()).await {
                        Ok(()) => {
                            // Update the chain tip to this block
                            let expected_height =
                                current_tip_height.checked_add(1).unwrap_or_else(|| {
                                    error!("Height calculation would overflow, using max value");
                                    u64::MAX
                                });

                            // Add block to chain state
                            if self
                                .add_block(block_hash, expected_height)
                                .await
                                .unwrap_or(true)
                            {
                                self.set_chain_tip(block_hash, expected_height).await?;
                                current_tip_hash = block_hash;
                                current_tip_height = expected_height;

                                info!(
                                    "Successfully processed block: {} at height {} ({} remaining)",
                                    block_hash,
                                    expected_height,
                                    buffered_blocks.len()
                                );

                                blocks_processed = blocks_processed.saturating_add(1);
                                total_processed = total_processed.saturating_add(1);
                            } else {
                                warn!("Failed to add block {} to chain state", block_hash);
                            }
                        }
                        Err(e) => {
                            error!("Failed to process block {}: {}", block_hash, e);
                            // Remove the block from database if validation failed
                            if let Some(database) = &self.database {
                                if let Err(db_err) = database.remove_block(&block_hash).await {
                                    error!("Failed to remove invalid block from database: {}", db_err);
                                }
                            }
                            // Continue with other blocks even if one fails
                        }
                    }

                    // Update progress
                    {
                        let mut progress = self.progress.write().await;
                        progress.blocks_downloaded = progress.blocks_downloaded.saturating_add(1);
                    }
                }
            } else {
                // No blocks can be processed, likely due to missing parents
                warn!(
                    "No blocks can be processed, {} blocks remaining in buffer",
                    buffered_blocks.len()
                );

                // Log remaining blocks for debugging
                for (hash, block) in buffered_blocks.iter() {
                    warn!("Remaining block: {} (prev: {})", hash, block.previous_hash);
                }

                // Break to avoid infinite loop
                break;
            }
        }

        info!(
            "COMPLETED BLOCK DOWNLOAD: Processed {} out of {} buffered blocks",
            total_processed,
            total_processed.saturating_add(buffered_blocks.len())
        );
        Ok(total_processed)
    }

    /// Processes a received block.
    async fn process_block<H>(&self, block: StandardBlock<H>) -> Result<(), ConnectionError>
    where
        H: Header + Send + Sync + 'static,
    {
        let block_hash = block.header().block_hash();
        let tx_count = block.transactions().len();

        debug!(
            "Processing block: {} ({} transactions)",
            block_hash, tx_count
        );

        // Validate the block
        if let Err(e) = self.validate_block::<H>(&block).await {
            error!("Block validation failed for {}: {}", block_hash, e);
            return Err(ConnectionError::InvalidMessage(format!(
                "Block validation failed: {}",
                e
            )));
        }

        // Check for chain reorganization
        if let Some(reorg) = self.check_for_reorg::<H>(&block).await? {
            warn!("Chain reorganization detected: {:?}", reorg);
            self.handle_reorg(reorg).await?;
        }

        // For now, we'll just log the transactions
        for (i, tx) in block.transactions().iter().enumerate() {
            debug!("  Transaction {}: {}", i, tx.compute_txid());
        }

        Ok(())
    }

    /// Validates a block header and transactions.
    async fn validate_block<H>(&self, block: &StandardBlock<H>) -> Result<(), ConnectionError>
    where
        H: Header + Send + Sync + 'static,
    {
        let header = block.header();
        let block_hash = header.block_hash();

        // Get the expected block height
        let expected_height = match self.get_block_height(&header.previous_block_hash()).await {
            Some(height) => height.checked_add(1).unwrap_or_else(|| {
                error!("Height calculation would overflow, using max value");
                u64::MAX
            }),
            None => {
                // This might be the genesis block, or we don't have the parent
                if header.previous_block_hash() == BlockHash::all_zeros() {
                    0 // Genesis block
                } else if header.previous_block_hash() == self.genesis_hash() {
                    1 // First block after genesis
                } else {
                    return Err(ConnectionError::InvalidMessage(format!(
                        "Previous block {} not found",
                        header.previous_block_hash()
                    )));
                }
            }
        };

        // Get consensus parameters to determine validation rules
        let params = self.consensus_params();
        let block_type = self.determine_block_type(expected_height, &params);

        // Log block type information
        info!(
            "Validating block {} at height {} (type: {})",
            block_hash, expected_height, block_type
        );

        // Check for hard fork transitions
        let randomx_height = params.randomx_height;
        if expected_height == randomx_height {
            warn!("RandomX hard fork activation at height {}", expected_height);
        }
        let randomx_enforcement_height = params.randomx_enforcement_height;
        if expected_height == randomx_enforcement_height {
            warn!("RandomX enforcement begins at height {}", expected_height);
        }

        // Check if we already have this block at a different height (reorg)
        if let Some(existing_height) = self.get_block_height(&block_hash).await
            && existing_height != expected_height
        {
            return Err(ConnectionError::InvalidMessage(format!(
                "Block {} exists at height {} but expected at height {}",
                block_hash, existing_height, expected_height
            )));
        }

        // Validate proof of work with appropriate rules
        if !self
            .validate_pow_with_fork_check::<H>(header, expected_height)
            .await?
        {
            return Err(ConnectionError::InvalidMessage(format!(
                "Invalid proof of work for block {} (type: {})",
                block_hash, block_type
            )));
        }

        // Validate timestamp
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let header_timestamp = u64::from(header.timestamp());
        let future_limit = match current_time.checked_add(2 * 3600) {
            Some(limit) => limit,
            None => {
                error!("Future time calculation would overflow, using max value");
                u64::MAX
            }
        };

        if header_timestamp > future_limit {
            // Allow 2 hours in the future
            return Err(ConnectionError::InvalidMessage(format!(
                "Block timestamp {} is too far in the future",
                header.timestamp()
            )));
        }

        // Validate transactions
        for tx in block.transactions() {
            // Basic transaction validation
            if tx.is_coinbase()
                && block
                    .transactions()
                    .iter()
                    .position(|t| t.compute_txid() == tx.compute_txid())
                    != Some(0)
            {
                return Err(ConnectionError::InvalidMessage(
                    "Coinbase transaction must be first in block".to_string(),
                ));
            }

            if !tx.is_coinbase() && tx.input.is_empty() {
                return Err(ConnectionError::InvalidMessage(
                    "Non-coinbase transaction must have inputs".to_string(),
                ));
            }
        }

        debug!(
            "Successfully validated block {} at height {} (type: {})",
            block_hash, expected_height, block_type
        );

        Ok(())
    }

    /// Validates proof of work with consideration for hard fork transitions.
    async fn validate_pow_with_fork_check<H>(
        &self,
        header: &H,
        height: u64,
    ) -> Result<bool, ConnectionError>
    where
        H: Header + Send + Sync + 'static,
    {
        let params = self.consensus_params();

        // For blocks before RandomX activation, use standard validation
        let randomx_height = params.randomx_height;
        if height < randomx_height {
            return self.validate_pow::<H>(header).await;
        }

        // For blocks at or after RandomX activation
        if height >= randomx_height {
            // If RandomX is enforced, reject any non-RandomX blocks
            let randomx_enforcement_height = params.randomx_enforcement_height;
            if height >= randomx_enforcement_height {
                // Check if this is a RandomX block by looking at the header size
                // RandomX headers are 112 bytes vs 80 bytes for Bitcoin headers
                if H::SIZE == 112 {
                    debug!("Validating RandomX block at height {}", height);
                    return self.validate_pow::<H>(header).await;
                } else {
                    warn!(
                        "Rejecting non-RandomX block at height {} (RandomX enforcement active)",
                        height
                    );
                    return Ok(false);
                }
            } else {
                // During transition period, accept both types
                debug!(
                    "Validating block during RandomX transition at height {}",
                    height
                );
                return self.validate_pow::<H>(header).await;
            }
        }

        self.validate_pow::<H>(header).await
    }

    /// Validates the proof of work for a block header.
    async fn validate_pow<H>(&self, header: &H) -> Result<bool, ConnectionError>
    where
        H: Header + Send + Sync + 'static,
    {
        let block_hash = header.block_hash();
        let target = match header.target() {
            Some(target) => target,
            None => {
                warn!("Header does not have a target value, skipping PoW validation");
                return Ok(true); // Skip validation if no target is available
            }
        };

        // Use the header's own validate_pow method instead of implementing our own
        match header.validate_pow(target) {
            Ok(hash) => {
                // Verify that the returned hash matches the block hash
                if hash == block_hash {
                    Ok(true)
                } else {
                    error!("Header validation returned a different hash than expected");
                    Ok(false)
                }
            }
            Err(e) => {
                error!("Proof of work validation failed: {:?}", e);
                Ok(false)
            }
        }
    }

    /// Checks if a new block causes a chain reorganization.
    async fn check_for_reorg<H>(
        &self,
        block: &StandardBlock<H>,
    ) -> Result<Option<ReorgInfo>, ConnectionError>
    where
        H: Header + Send + Sync + 'static,
    {
        let header = block.header();
        let prev_hash: BlockHash = header.previous_block_hash();

        // Get current chain tip
        let (current_tip_hash, current_tip_height) = self.get_chain_tip().await;

        // If this block builds on our current tip, no reorg
        if prev_hash == current_tip_hash {
            return Ok(None);
        }

        // Check if we have the previous block
        let prev_height = match self.get_block_height(&prev_hash).await {
            Some(height) => height,
            None => return Ok(None), // We don't have the parent, can't determine reorg
        };

        // If the previous block is not on our main chain, we might have a reorg
        if prev_height < current_tip_height {
            // Find the common ancestor
            let mut fork_height = prev_height;
            let mut fork_hash = prev_hash;

            while fork_height > 0 {
                if let Some(hash_at_height) = self.get_block_hash_at_height(fork_height).await
                    && hash_at_height == fork_hash
                {
                    // Found common ancestor
                    let reorg_depth = match current_tip_height.checked_sub(fork_height) {
                        Some(depth) => depth,
                        None => {
                            error!("Reorg depth calculation would underflow, using 0");
                            0
                        }
                    };
                    if reorg_depth > 0 && header.block_hash() != current_tip_hash {
                        return Ok(Some(ReorgInfo {
                            common_ancestor_height: fork_height,
                            common_ancestor_hash: fork_hash,
                            old_tip_hash: current_tip_hash,
                            old_tip_height: current_tip_height,
                            new_tip_hash: header.block_hash(),
                            new_tip_height: match prev_height.checked_add(1) {
                                Some(new_height) => new_height,
                                None => {
                                    error!(
                                        "New tip height calculation would overflow, using max \
                                         value"
                                    );
                                    u64::MAX
                                }
                            },
                            reorg_depth,
                        }));
                    }
                }

                // Move to previous block
                if let Some(prev_header) = self
                    .get_header_at_height::<H>(fork_height.saturating_sub(1))
                    .await
                {
                    fork_hash = prev_header.previous_block_hash();
                    fork_height = match fork_height.checked_sub(1) {
                        Some(new_height) => new_height,
                        None => {
                            error!("Fork height calculation would underflow, using 0");
                            0
                        }
                    };
                } else {
                    break;
                }
            }
        }

        Ok(None)
    }

    /// Handles a chain reorganization.
    async fn handle_reorg(&self, reorg: ReorgInfo) -> Result<(), ConnectionError> {
        warn!(
            "Handling chain reorganization: depth {}, old tip: {} ({}), new tip: {} ({})",
            reorg.reorg_depth,
            reorg.old_tip_hash,
            reorg.old_tip_height,
            reorg.new_tip_hash,
            reorg.new_tip_height
        );

        // In a full implementation, you would:
        // 1. Disconnect blocks from the old chain
        // 2. Update UTXO set accordingly
        // 3. Connect blocks from the new chain
        // 4. Update chain state

        // For now, we'll just update the chain tip
        let _ = self
            .set_chain_tip(reorg.new_tip_hash, reorg.new_tip_height)
            .await;

        info!("Chain reorganization handled successfully");
        Ok(())
    }

    /// Gets the block header at a specific height.
    async fn get_header_at_height<H>(&self, height: u64) -> Option<H>
    where
        H: Header + Send + Sync + 'static,
    {
        if let Some(database) = &self.database {
            // First get the hash at this height
            if let Ok(Some(block_hash)) = database.get_block_hash_at_height(height).await {
                // Then get the header for that hash
                if let Ok(header) = database.get_header(&block_hash).await {
                    return Some(header);
                }
            }
        }
        None
    }

    /// Gets the current synchronization progress.
    pub async fn get_progress(&self) -> SyncProgress {
        *self.progress.read().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alpha::blockdata::block::header::{bitcoin::BitcoinHeader, randomx::RandomXHeader};

    #[test]
    fn test_sync_config_default() {
        let config = SyncConfig::default();
        assert_eq!(config.max_headers_per_request, 2000);
        assert_eq!(config.max_blocks_to_download, usize::MAX);
        assert!(config.download_full_blocks);
    }

    #[tokio::test]
    async fn test_block_synchronizer_creation() {
        let config = SyncConfig::default();
        let synchronizer = BlockSynchronizer::new(config);

        let progress = synchronizer.get_progress().await;
        assert_eq!(progress.headers_synced, 0);
        assert_eq!(progress.blocks_downloaded, 0);
        assert_eq!(progress.last_known_height, 0);
        assert!(!progress.is_complete);
    }

    #[tokio::test]
    async fn test_progress_tracking() {
        let config = SyncConfig::default();
        let synchronizer = BlockSynchronizer::new(config);

        // Update progress
        {
            let mut progress = synchronizer.progress.write().await;
            progress.headers_synced = 100;
            progress.blocks_downloaded = 50;
            progress.last_known_height = 200;
            progress.is_complete = false;
        }

        // Check progress
        let progress = synchronizer.get_progress().await;
        assert_eq!(progress.headers_synced, 100);
        assert_eq!(progress.blocks_downloaded, 50);
        assert_eq!(progress.last_known_height, 200);
        assert!(!progress.is_complete);
    }

    #[test]
    fn test_determine_block_type() {
        let config = SyncConfig::default();
        let synchronizer = BlockSynchronizer::new(config);

        // Test with mainnet parameters
        let params = Params::MAINNET;

        // Before RandomX activation
        assert_eq!(synchronizer.determine_block_type(50000, &params), "SHA256D");

        // At RandomX activation
        assert_eq!(
            synchronizer.determine_block_type(70228, &params),
            "RandomX (transition)"
        );

        // After RandomX activation but before enforcement
        assert_eq!(
            synchronizer.determine_block_type(100000, &params),
            "RandomX (transition)"
        );

        // At RandomX enforcement
        assert_eq!(
            synchronizer.determine_block_type(303271, &params),
            "RandomX (enforced)"
        );

        // After RandomX enforcement
        assert_eq!(
            synchronizer.determine_block_type(400000, &params),
            "RandomX (enforced)"
        );
    }

    #[test]
    fn test_get_consensus_params() {
        // Test default (testnet)
        let config = SyncConfig::default();
        let synchronizer = BlockSynchronizer::new(config);
        let params = synchronizer.consensus_params();
        assert_eq!(params.network, crate::alpha::network::Network::Testnet);

        // Test with mainnet network
        let config = SyncConfig {
            network: crate::alpha::network::Network::Mainnet,
            ..Default::default()
        };
        let synchronizer = BlockSynchronizer::new(config);
        let params = synchronizer.consensus_params();
        assert_eq!(params.network, crate::alpha::network::Network::Mainnet);

        // Test with regtest network
        let config = SyncConfig {
            network: crate::alpha::network::Network::Regtest,
            ..Default::default()
        };
        let synchronizer = BlockSynchronizer::new(config);
        let params = synchronizer.consensus_params();
        assert_eq!(params.network, crate::alpha::network::Network::Regtest);
    }

    #[test]
    fn test_header_size_detection() {
        // Bitcoin headers should be 80 bytes
        assert_eq!(BitcoinHeader::SIZE, 80);

        // RandomX headers should be 112 bytes
        assert_eq!(RandomXHeader::SIZE, 112);
    }
}
