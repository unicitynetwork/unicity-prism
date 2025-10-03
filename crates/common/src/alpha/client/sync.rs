//! Block synchronization implementation for Bitcoin P2P protocol.
//!
//! This module provides functionality for synchronizing blockchain data with
//! peers, including requesting block headers using GetHeaders and downloading
//! full blocks using GetData messages.

use std::{collections::HashSet, sync::Arc};

use tokio::{net::TcpStream, sync::RwLock};
use tracing::{debug, info, warn};

use crate::alpha::{
    blockdata::block::{BlockHash, Header},
    client::{
        connection::{ConnectionError, ConnectionManager},
        message::{
            Message, Request, Response,
            get_data::{GetData, Inventory},
            request::GetHeaders,
            response::{Headers, StandardBlock, block::Block},
        },
    },
    hashes::Hash,
};

/// Configuration for block synchronization.
#[derive(Debug, Clone, Copy)]
pub struct SyncConfig {
    /// Maximum number of block headers to request in a single GetHeaders
    /// message.
    pub max_headers_per_request: usize,
    /// Maximum number of blocks to download.
    pub max_blocks_to_download: usize,
    /// Whether to download full blocks or just headers.
    pub download_full_blocks: bool,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            max_headers_per_request: 2000, // Alpha protocol limit
            max_blocks_to_download: 1000,
            download_full_blocks: true,
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
    /// Whether synchronization is complete.
    pub is_complete: bool,
}

/// Handles blockchain synchronization with peers.
#[derive(Debug)]
pub struct BlockSynchronizer {
    config: SyncConfig,
    progress: Arc<RwLock<SyncProgress>>,
    known_block_hashes: Arc<RwLock<HashSet<BlockHash>>>,
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
                is_complete: false,
            })),
            known_block_hashes: Arc::new(RwLock::new(HashSet::new())),
        }
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

        // Update progress with peer's best height
        {
            let mut progress = self.progress.write().await;
            progress.last_known_height = u64::try_from(peer_best_height).unwrap_or(0);
        }

        // Start with the genesis block hash
        let mut locator_hashes = vec![BlockHash::all_zeros()];

        // Request headers in batches
        let mut total_headers_synced: usize = 0;
        let mut stop_hash = None;

        loop {
            // Request headers
            let headers = self
                .request_headers::<H>(connection, stream, locator_hashes.clone(), stop_hash)
                .await?;

            // If no headers returned, we're done
            if headers.is_empty() {
                info!("No more headers available, synchronization complete");
                break;
            }

            // Process headers
            let headers_count = headers.len();
            total_headers_synced = total_headers_synced.saturating_add(headers_count);

            // Update progress
            {
                let mut progress = self.progress.write().await;
                progress.headers_synced = total_headers_synced;
            }

            info!(
                "Received {} headers (total: {})",
                headers_count, total_headers_synced
            );

            // If we're not downloading full blocks, we're done
            if !self.config.download_full_blocks {
                info!("Header-only synchronization complete");
                break;
            }

            // If we've reached our limit, stop
            if total_headers_synced >= self.config.max_blocks_to_download {
                info!("Reached maximum block limit, stopping synchronization");
                break;
            }

            // Download full blocks for these headers
            if self.config.download_full_blocks {
                self.download_blocks::<H>(connection, stream, headers.headers())
                    .await?;
            }

            // Update locator hashes for next request
            if let Some(last_header) = headers.headers().last() {
                locator_hashes = vec![last_header.block_hash()];
                stop_hash = None; // Continue until we reach the peer's best height
            }
        }

        // Mark synchronization as complete
        {
            let mut progress = self.progress.write().await;
            progress.is_complete = true;
        }

        info!(
            "Block synchronization complete ({} headers, {} blocks)",
            total_headers_synced,
            self.progress.read().await.blocks_downloaded
        );

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

    /// Downloads full blocks for the given headers.
    async fn download_blocks<H>(
        &self,
        connection: &ConnectionManager,
        stream: &mut TcpStream,
        headers: &[H],
    ) -> Result<(), ConnectionError>
    where
        H: Header + Send + Sync + 'static + std::fmt::Debug,
    {
        debug!("Downloading {} blocks", headers.len());

        // Create inventory vectors for block requests
        let mut inventories = Vec::new();
        let mut block_hashes = Vec::new();

        for header in headers {
            let block_hash = header.block_hash();

            // Skip if we already know about this block
            {
                let known_hashes = self.known_block_hashes.read().await;
                if known_hashes.contains(&block_hash) {
                    continue;
                }
            }

            inventories.push(Inventory::Block(block_hash));
            block_hashes.push(block_hash);

            // Mark as known to avoid duplicate requests
            {
                let mut known_hashes = self.known_block_hashes.write().await;
                known_hashes.insert(block_hash);
            }
        }

        if inventories.is_empty() {
            debug!("No new blocks to download");
            return Ok(());
        }

        // Send GetData request
        let get_data = GetData::new(inventories);
        connection
            .send_message(stream, Message::<H>::Request(Request::GetData(get_data)))
            .await?;

        // Wait for block responses
        let mut blocks_received: i32 = 0;
        let expected_blocks = block_hashes.len();

        while blocks_received < i32::try_from(expected_blocks).unwrap_or(i32::MAX) {
            let message = connection.receive_message::<H>(stream).await?;

            match message {
                Message::Response(Response::Block(block)) => {
                    let block_hash = block.header().block_hash();

                    // Check if this is one of the blocks we requested
                    if block_hashes.contains(&block_hash) {
                        blocks_received = blocks_received.saturating_add(1);

                        // Update progress
                        {
                            let mut progress = self.progress.write().await;
                            progress.blocks_downloaded =
                                progress.blocks_downloaded.saturating_add(1);
                        }

                        // Log block information
                        info!(
                            "Received block: {} (height: {})",
                            block_hash,
                            self.get_block_height(block_hash)
                        );

                        // Process block transactions
                        self.process_block(Box::new(StandardBlock {
                            header: block.header,
                            transactions: block.transactions,
                        }))
                        .await?;
                    } else {
                        warn!("Received unexpected block: {}", block_hash);
                    }
                }
                Message::Response(Response::NotFound(not_found)) => {
                    // Handle case where peer doesn't have the block
                    warn!("Peer doesn't have requested block(s): {:?}", not_found);
                    blocks_received = blocks_received.saturating_add(1); // Count as processed to avoid infinite loop
                }
                _ => {
                    debug!(
                        "Received non-block message during block download: {:?}",
                        message
                    );
                    continue;
                }
            }
        }

        debug!("Downloaded {} blocks", blocks_received);
        Ok(())
    }

    /// Processes a received block.
    async fn process_block<H>(&self, block: Box<dyn Block<H>>) -> Result<(), ConnectionError>
    where
        H: Header + Send + Sync + 'static,
    {
        let block_hash = block.header().block_hash();
        let tx_count = block.transactions().len();

        debug!(
            "Processing block: {} ({} transactions)",
            block_hash, tx_count
        );

        // Here you would typically:
        // 1. Validate the block
        // 2. Add it to the local blockchain
        // 3. Update the UTXO set
        // 4. Notify other components about the new block

        // For now, we'll just log the transactions
        for (i, tx) in block.transactions().iter().enumerate() {
            debug!("  Transaction {}: {}", i, tx.compute_txid());
        }

        Ok(())
    }

    /// Gets the current synchronization progress.
    pub async fn get_progress(&self) -> SyncProgress {
        *self.progress.read().await
    }

    /// Estimates the height of a block based on its hash.
    /// This is a placeholder implementation - in a real node, you would
    /// maintain a mapping of block hashes to heights.
    fn get_block_height(&self, _block_hash: BlockHash) -> u64 {
        // Placeholder - would need to implement proper height tracking
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_config_default() {
        let config = SyncConfig::default();
        assert_eq!(config.max_headers_per_request, 2000);
        assert_eq!(config.max_blocks_to_download, 1000);
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
}
