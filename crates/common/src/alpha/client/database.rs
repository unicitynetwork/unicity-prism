//! Database module for blockchain storage using redb.
//!
//! This module provides a persistent storage layer for blockchain data using
//! the redb key-value database. It stores blocks, headers, and chain state
//! in an efficient binary format.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use redb::{
    CommitError, Database, DatabaseError as RedbError, ReadableTable, ReadableTableMetadata,
    StorageError, TableDefinition, TableError, TransactionError,
};
use serde::{Deserialize, Serialize};
use serde_json;
use thiserror::Error;
use tracing::{debug, error, info};

use crate::alpha::{
    blockdata::block::{BlockHash, Header},
    client::message::response::block::{Block, StandardBlock},
    consensus::{Decodable, EncodeDecodeError},
    hashes::Hash,
    io::Error as IoError,
};

/// Database error types.
///
/// This enum represents all possible errors that can occur during database
/// operations in the blockchain storage layer. It wraps various underlying
/// error types and provides domain-specific errors for blockchain operations.
#[derive(Debug, Error)]
pub enum DatabaseError {
    /// Error from the underlying redb database engine.
    ///
    /// This variant wraps errors that originate from the redb key-value store,
    /// such as corruption, permission issues, or other database-level problems.
    #[error("Database error: {0}")]
    Redb(#[from] RedbError),

    /// Error during database transaction operations.
    ///
    /// This occurs when a transaction cannot be started, completed, or rolled
    /// back due to conflicts, timeouts, or other transaction-related
    /// issues.
    #[error("Transaction error: {0}")]
    Transaction(#[from] TransactionError),

    /// Error when committing a transaction to the database.
    ///
    /// This occurs specifically during the commit phase of a transaction when
    /// changes cannot be durably persisted to storage.
    #[error("Commit error: {0}")]
    CommitError(#[from] CommitError),

    /// Error related to storage operations.
    ///
    /// This includes issues with the underlying storage medium, such as disk
    /// full errors, I/O failures at the storage layer, or corruption.
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    /// Error when accessing or manipulating database tables.
    ///
    /// This occurs when table operations fail, such as when a table doesn't
    /// exist, schema mismatches, or table-specific constraints are
    /// violated.
    #[error("Table error: {0}")]
    Table(#[from] TableError),

    /// Error during encoding or decoding of blockchain data.
    ///
    /// This occurs when serializing data for storage or deserializing data from
    /// storage fails due to format issues, version mismatches, or
    /// corruption.
    #[error("Encoding error: {0}")]
    Encoding(#[from] EncodeDecodeError),

    /// Error during I/O operations.
    ///
    /// This wraps standard I/O errors that may occur during file operations,
    /// such as reading from or writing to the database files.
    #[error("IO error: {0}")]
    Io(#[from] IoError),

    /// Error when a requested block is not found in the database.
    ///
    /// This is a domain-specific error that occurs when attempting to retrieve
    /// a block by its hash, but the block does not exist in the database.
    #[error("Block not found: {0}")]
    BlockNotFound(BlockHash),

    /// Error indicating an invalid or inconsistent database state.
    ///
    /// This is a general-purpose error for when the database contents don't
    /// match expected invariants, such as corrupted chain state or
    /// inconsistent mappings.
    #[error("Invalid database state: {0}")]
    InvalidState(String),
}

impl From<std::io::Error> for DatabaseError {
    fn from(err: std::io::Error) -> Self {
        DatabaseError::Io(err.into())
    }
}

impl From<serde_json::Error> for DatabaseError {
    fn from(err: serde_json::Error) -> Self {
        DatabaseError::InvalidState(format!("JSON serialization/deserialization error: {}", err))
    }
}

/// Result type for database operations.
///
/// This type alias is used throughout the database module to simplify error
/// handling. It represents the result of a database operation that can either
/// succeed with a value of type T or fail with a [`DatabaseError`].
///
/// # Examples
///
/// ```rust
/// use crate::alpha::client::database::{DatabaseResult, DatabaseError};
///
/// fn get_block_height() -> DatabaseResult<u64> {
///     // Implementation that returns either a height or a DatabaseError
///     Ok(100)
/// }
/// ```
pub type DatabaseResult<T> = Result<T, DatabaseError>;

/// Table definitions for the database.
const BLOCKS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("blocks");
const HEADERS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("headers");
const CHAIN_STATE_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("chain_state");
const BLOCK_HEIGHTS_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("block_heights");
const HEIGHT_HASHES_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("height_hashes");

/// Persistent storage for blockchain state using redb.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainState {
    /// Map of block hash to height
    pub block_heights: std::collections::HashMap<BlockHash, u64>,
    /// Map of height to block hash
    pub height_hashes: std::collections::HashMap<u64, BlockHash>,
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
            block_heights: std::collections::HashMap::new(),
            height_hashes: std::collections::HashMap::new(),
            tip_hash: BlockHash::all_zeros(),
            tip_height: 0,
            last_sync: 0,
        }
    }
}

/// Database wrapper for blockchain storage.
#[derive(Debug)]
pub struct BlockDatabase {
    db: Arc<Database>,
    path: PathBuf,
}

impl BlockDatabase {
    /// Opens or creates a database at the specified path.
    pub async fn open<P: AsRef<Path>>(path: P) -> DatabaseResult<Self> {
        let path = path.as_ref().to_path_buf();

        // Create parent directories if they don't exist
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let db = Arc::new(Database::create(&path)?);

        // Initialize tables
        let write_txn = db.begin_write()?;
        {
            write_txn.open_table(BLOCKS_TABLE)?;
            write_txn.open_table(HEADERS_TABLE)?;
            write_txn.open_table(CHAIN_STATE_TABLE)?;
            write_txn.open_table(BLOCK_HEIGHTS_TABLE)?;
            write_txn.open_table(HEIGHT_HASHES_TABLE)?;
        }
        write_txn.commit()?;

        info!("Opened blockchain database at: {}", path.display());

        Ok(Self { db, path })
    }

    /// Gracefully shuts down the database.
    pub async fn shutdown(&self) -> DatabaseResult<()> {
        info!("Shutting down database at: {}", self.path.display());

        // redb doesn't have an explicit close method
        // The database will be closed when all references are dropped

        info!("Database shutdown initiated");
        Ok(())
    }

    /// Gets the database path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Stores a block in the database.
    pub async fn store_block<H: Header, B: Block<H>>(&self, block: &B) -> DatabaseResult<()> {
        let block_hash = block.header().block_hash();
        let block_hash_bytes = block_hash.to_byte_array();

        // Serialize the block
        let mut block_data = Vec::new();
        block.consensus_encode(&mut block_data)?;

        let write_txn = self.db.begin_write()?;
        {
            let mut blocks_table = write_txn.open_table(BLOCKS_TABLE)?;
            blocks_table.insert(&block_hash_bytes[..], &block_data[..])?;
        }
        write_txn.commit()?;

        debug!("Stored block: {}", block_hash);
        Ok(())
    }

    /// Retrieves a block from the database.
    pub async fn get_block<H: Header>(
        &self,
        hash: &BlockHash,
    ) -> DatabaseResult<Box<StandardBlock<H>>> {
        let hash_bytes = hash.to_byte_array();

        let read_txn = self.db.begin_read()?;
        let blocks_table = read_txn.open_table(BLOCKS_TABLE)?;

        if let Some(block_data) = blocks_table.get(&hash_bytes[..])? {
            let block_data = block_data.value();

            // For now, we'll return a StandardBlock
            // In a full implementation, you'd need to determine the block type
            // and deserialize accordingly
            let mut cursor = std::io::Cursor::new(block_data);
            let block = StandardBlock::<H>::consensus_decode(&mut cursor)?;

            Ok(Box::new(block))
        } else {
            Err(DatabaseError::BlockNotFound(*hash))
        }
    }

    /// Stores a block header in the database.
    pub async fn store_header<H: Header>(&self, header: &H) -> DatabaseResult<()> {
        let block_hash = header.block_hash();
        let hash_bytes = block_hash.to_byte_array();

        // Serialize the header
        let mut header_data = Vec::new();
        header.consensus_encode(&mut header_data)?;

        let write_txn = self.db.begin_write()?;
        {
            let mut headers_table = write_txn.open_table(HEADERS_TABLE)?;
            headers_table.insert(&hash_bytes[..], &header_data[..])?;
        }
        write_txn.commit()?;

        debug!("Stored header: {}", block_hash);
        Ok(())
    }

    /// Retrieves a block header from the database.
    pub async fn get_header<H: Header>(&self, hash: &BlockHash) -> DatabaseResult<H> {
        let hash_bytes = hash.to_byte_array();

        let read_txn = self.db.begin_read()?;
        let headers_table = read_txn.open_table(HEADERS_TABLE)?;

        if let Some(header_data) = headers_table.get(&hash_bytes[..])? {
            let header_data = header_data.value();
            let mut cursor = std::io::Cursor::new(header_data);
            let header = H::consensus_decode(&mut cursor)?;
            Ok(header)
        } else {
            Err(DatabaseError::BlockNotFound(*hash))
        }
    }

    /// Stores the chain state in the database.
    pub async fn store_chain_state(&self, state: &ChainState) -> DatabaseResult<()> {
        let state_data = serde_json::to_vec(state)?;

        let write_txn = self.db.begin_write()?;
        {
            let mut state_table = write_txn.open_table(CHAIN_STATE_TABLE)?;
            state_table.insert("current", &state_data[..])?;

            // Also store individual mappings for efficient lookup
            let mut heights_table = write_txn.open_table(BLOCK_HEIGHTS_TABLE)?;
            let mut hashes_table = write_txn.open_table(HEIGHT_HASHES_TABLE)?;

            // Clear existing mappings
            let heights_to_remove: Vec<u64> = heights_table
                .iter()?
                .map(|result| result.map(|(height, _)| height.value()))
                .collect::<Result<_, _>>()?;
            for height in heights_to_remove {
                heights_table.remove(height)?;
            }

            let hashes_to_remove: Vec<u64> = hashes_table
                .iter()?
                .map(|result| result.map(|(height, _)| height.value()))
                .collect::<Result<_, _>>()?;
            for height in hashes_to_remove {
                hashes_table.remove(height)?;
            }

            // Insert new mappings
            for (hash, height) in &state.block_heights {
                heights_table.insert(*height, &hash.to_byte_array()[..])?;
            }
            for (height, hash) in &state.height_hashes {
                hashes_table.insert(*height, &hash.to_byte_array()[..])?;
            }
        }
        write_txn.commit()?;

        debug!("Stored chain state: tip height {}", state.tip_height);
        Ok(())
    }

    /// Retrieves the chain state from the database.
    pub async fn get_chain_state(&self) -> DatabaseResult<ChainState> {
        let read_txn = self.db.begin_read()?;
        let state_table = read_txn.open_table(CHAIN_STATE_TABLE)?;

        if let Some(state_data) = state_table.get("current")? {
            let state_data = state_data.value();
            let state: ChainState = serde_json::from_slice(state_data)?;
            Ok(state)
        } else {
            // Return default state if not found
            Ok(ChainState::default())
        }
    }

    /// Gets the height of a block hash.
    pub async fn get_block_height(&self, hash: &BlockHash) -> DatabaseResult<Option<u64>> {
        let read_txn = self.db.begin_read()?;
        let heights_table = read_txn.open_table(BLOCK_HEIGHTS_TABLE)?;

        // We need to scan through the table to find the hash
        for result in heights_table.iter()? {
            let (height, stored_hash) = result?;
            let stored_hash_bytes = stored_hash.value();
            if stored_hash_bytes == &hash.to_byte_array()[..] {
                return Ok(Some(height.value()));
            }
        }

        Ok(None)
    }

    /// Gets the block hash at a specific height.
    pub async fn get_block_hash_at_height(&self, height: u64) -> DatabaseResult<Option<BlockHash>> {
        let read_txn = self.db.begin_read()?;
        let hashes_table = read_txn.open_table(HEIGHT_HASHES_TABLE)?;

        if let Some(hash_bytes) = hashes_table.get(height)? {
            let hash_bytes = hash_bytes.value();
            let mut hash_array = [0u8; 32];
            hash_array.copy_from_slice(hash_bytes);
            Ok(Some(BlockHash::from_byte_array(hash_array)))
        } else {
            Ok(None)
        }
    }

    /// Checks if a block exists in the database.
    pub async fn block_exists(&self, hash: &BlockHash) -> DatabaseResult<bool> {
        let hash_bytes = hash.to_byte_array();

        let read_txn = self.db.begin_read()?;
        let blocks_table = read_txn.open_table(BLOCKS_TABLE)?;
        Ok(blocks_table.get(&hash_bytes[..])?.is_some())
    }

    /// Gets the current chain tip.
    pub async fn get_chain_tip(&self) -> DatabaseResult<(BlockHash, u64)> {
        let state = self.get_chain_state().await?;
        Ok((state.tip_hash, state.tip_height))
    }

    /// Sets the chain tip.
    pub async fn set_chain_tip(&self, hash: BlockHash, height: u64) -> DatabaseResult<()> {
        let mut state = self.get_chain_state().await?;
        state.tip_hash = hash;
        state.tip_height = height;
        state.block_heights.insert(hash, height);
        state.height_hashes.insert(height, hash);
        state.last_sync = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.store_chain_state(&state).await
    }

    /// Adds a block to the chain state.
    pub async fn add_block_to_state(&self, hash: BlockHash, height: u64) -> DatabaseResult<bool> {
        let mut state = self.get_chain_state().await?;

        // Check if block already exists
        if state.block_heights.contains_key(&hash) {
            return Ok(false);
        }

        // Add block to state
        state.block_heights.insert(hash, height);
        state.height_hashes.insert(height, hash);

        // Update tip if this is higher
        if height > state.tip_height {
            state.tip_hash = hash;
            state.tip_height = height;
        }

        state.last_sync = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.store_chain_state(&state).await?;
        Ok(true)
    }

    /// Migrates data from JSON files to the database.
    pub async fn migrate_from_json<P: AsRef<Path>>(&self, data_dir: P) -> DatabaseResult<()> {
        let data_dir = data_dir.as_ref();
        let state_file = data_dir.join("chain_state.json");

        if state_file.exists() {
            info!("Migrating chain state from JSON to database");

            let content = tokio::fs::read_to_string(&state_file).await?;
            let state: ChainState = serde_json::from_str(&content)?;

            self.store_chain_state(&state).await?;

            // Create a backup of the old file
            let backup_file = data_dir.join("chain_state.json.backup");
            tokio::fs::rename(&state_file, &backup_file).await?;

            info!("Migration completed successfully");
        }

        Ok(())
    }

    /// Performs database maintenance (compaction, etc.).
    pub async fn maintenance(&self) -> DatabaseResult<()> {
        info!("Performing database maintenance");

        // redb automatically handles compaction, but we can add
        // any additional maintenance tasks here

        Ok(())
    }

    /// Gets database statistics.
    pub async fn get_stats(&self) -> DatabaseResult<DatabaseStats> {
        let read_txn = self.db.begin_read()?;

        let blocks_table = read_txn.open_table(BLOCKS_TABLE)?;
        let headers_table = read_txn.open_table(HEADERS_TABLE)?;
        let heights_table = read_txn.open_table(BLOCK_HEIGHTS_TABLE)?;

        let block_count = blocks_table.len()?;
        let header_count = headers_table.len()?;
        let height_count = heights_table.len()?;

        let state = self.get_chain_state().await?;

        Ok(DatabaseStats {
            block_count,
            header_count,
            height_count,
            tip_height: state.tip_height,
            tip_hash: state.tip_hash,
            last_sync: state.last_sync,
        })
    }
}

/// Database statistics.
#[derive(Debug, Clone, Copy)]
pub struct DatabaseStats {
    /// Number of blocks stored
    pub block_count: u64,
    /// Number of headers stored
    pub header_count: u64,
    /// Number of height mappings
    pub height_count: u64,
    /// Current tip height
    pub tip_height: u64,
    /// Current tip hash
    pub tip_hash: BlockHash,
    /// Last sync timestamp
    pub last_sync: u64,
}

#[cfg(test)]
mod tests {
    use bitcoin::BlockHash;
    use tempfile::TempDir;

    use super::*;

    #[tokio::test]
    async fn test_database_creation() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");

        let db = BlockDatabase::open(&db_path).await.unwrap();
        assert_eq!(db.path(), db_path);
    }

    #[tokio::test]
    async fn test_chain_state_storage() {
        let temp_dir = TempDir::new().unwrap();
        let db = BlockDatabase::open(temp_dir.path().join("test.db"))
            .await
            .unwrap();

        let state = ChainState {
            tip_height: 100,
            tip_hash: BlockHash::all_zeros(),
            ..Default::default()
        };

        db.store_chain_state(&state).await.unwrap();

        let retrieved = db.get_chain_state().await.unwrap();
        assert_eq!(retrieved.tip_height, 100);
        assert_eq!(retrieved.tip_hash, state.tip_hash);
    }

    #[tokio::test]
    async fn test_block_height_mapping() {
        let temp_dir = TempDir::new().unwrap();
        let db = BlockDatabase::open(temp_dir.path().join("test.db"))
            .await
            .unwrap();

        let hash = BlockHash::all_zeros();
        db.add_block_to_state(hash, 50).await.unwrap();

        let height = db.get_block_height(&hash).await.unwrap().unwrap();
        assert_eq!(height, 50);

        let retrieved_hash = db.get_block_hash_at_height(50).await.unwrap().unwrap();
        assert_eq!(retrieved_hash, hash);
    }
}
