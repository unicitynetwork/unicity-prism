mod header;

use crate::blockdata::transaction::Transaction;
use crate::consensus::{Decodable, Encodable, EncodeDecodeError};
use crate::hashes::{hash_newtype, sha256d};
use crate::io::{Error as IoError, Read, Write};
pub use bitcoin::block::{BlockHash, ValidationError, WitnessMerkleNode};
pub use header::{BitcoinHeader, Header, RandomXHeader};

/// Denotes in the block header if it is a RandomX block, or not.
const RX_VERSIONBIT: i32 = 0x02;

hash_newtype! {
    /// A hash type for RandomX blocks, based on SHA-256d.
    pub struct RandomXHash(sha256d::Hash);
}

impl Encodable for RandomXHash {
    fn consensus_encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, IoError> {
        self.0.consensus_encode(writer)
    }
}

impl Decodable for RandomXHash {
    fn consensus_decode<R: Read + ?Sized>(reader: &mut R) -> Result<Self, EncodeDecodeError> {
        use bitcoin::hashes::Hash;
        Ok(Self::from_byte_array(
            <<RandomXHash as Hash>::Bytes>::consensus_decode(reader)?,
        ))
    }
}

/// Represents a block in the blockchain.
///
/// A `Block` contains:
/// - The header of the block, which includes metadata like timestamp and previous block hash
/// - A list of transactions contained within the block
/// - An optional witness root, used for transaction witness data verification
///
/// # Example Usage
///
/// ```rust
/// use bitcoin::blockdata::transaction::{Transaction, TxIn, TxOut};
/// use bitcoin::hashes::sha256d;
/// use bitcoin::blockdata::block::{Block, Header};
///
/// // Create a simple block with one transaction
/// let tx = Transaction {
///     version: bitcoin::blockdata::transaction::Version::ONE,
///     lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
///     input: vec![],
///     output: vec![],
/// };
///
/// // Create a block with the transaction
/// let block = Block {
///     transactions: vec![tx],
///     witness_root: None,
/// };
///
/// // Accessing block data
/// let tx_count = block.transactions.len();
/// println!("Block contains {} transactions", tx_count);
/// ```
#[derive(Clone, Debug)]
pub struct Block {
    /// The block header
    // pub header: Header,
    /// List of transactions contained in the block
    pub transactions: Vec<Transaction>,
    /// Cached witness root, if it's been computed
    pub witness_root: Option<WitnessMerkleNode>,
}

impl Block {
    /// Creates a new empty block with no transactions
    pub fn new() -> Self {
        Block {
            transactions: vec![],
            witness_root: None,
        }
    }

    /// Creates a new block with the specified transactions
    pub fn with_transactions(transactions: Vec<Transaction>) -> Self {
        Block {
            transactions,
            witness_root: None,
        }
    }

    /// Adds a transaction to the block
    pub fn add_transaction(&mut self, tx: Transaction) {
        self.transactions.push(tx);
    }

    /// Gets the number of transactions in the block
    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }

    /// Gets a reference to the transactions
    pub fn transactions(&self) -> &[Transaction] {
        &self.transactions
    }

    /// Gets a mutable reference to the transactions
    pub fn transactions_mut(&mut self) -> &mut Vec<Transaction> {
        &mut self.transactions
    }
}
