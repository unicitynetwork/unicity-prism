mod header;

pub use bitcoin::block::{BlockHash, ValidationError, WitnessMerkleNode};
pub use header::{BitcoinHeader, Header, RandomXHeader};

use crate::alpha::{
    blockdata::transaction::Transaction,
    consensus::{Decodable, Encodable, EncodeDecodeError},
    hashes::{Sha256Hash, hash_newtype},
    io::{Error as IoError, Read, Write},
};

/// Type alias for a Bitcoin block.
pub type BitcoinBlock = Block<BitcoinHeader>;

/// Type alias for a RandomX block.
pub type RandomXBlock = Block<RandomXHeader>;

/// Denotes in the block header if it is a RandomX block, or not.
#[allow(dead_code)]
const RX_VERSIONBIT: i32 = 0x02;

hash_newtype! {
    /// A hash type for RandomX blocks, based on SHA-256d.
    pub struct RandomXHash(Sha256Hash);
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
/// - The header of the block, which includes metadata like timestamp and
///   previous block hash
/// - A list of transactions contained within the block
/// - An optional witness root, used for transaction witness data verification
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block<H: Header> {
    /// The block header
    pub header: H,
    /// List of transactions contained in the block
    pub transactions: Vec<Transaction>,
    /// Cached witness root, if it's been computed
    pub witness_root: Option<WitnessMerkleNode>,
}

impl<H: Header> Block<H> {
    /// Creates a new empty block with no transactions
    pub fn new(
        header: H,
        transactions: Vec<Transaction>,
        witness_root: Option<WitnessMerkleNode>,
    ) -> Self {
        Block {
            header,
            transactions,
            witness_root,
        }
    }

    /// Creates a new block with the specified transactions
    pub fn with_transactions(header: H, transactions: Vec<Transaction>) -> Self {
        Block {
            header,
            transactions,
            witness_root: None,
        }
    }

    /// Gets a reference to the block header
    pub fn header(&self) -> &H {
        &self.header
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

#[allow(
    clippy::arithmetic_side_effects,
    reason = "Won't fail on usize addition"
)]
impl<H: Header> Encodable for Block<H> {
    fn consensus_encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, IoError> {
        let mut len: usize = 0;

        // Encode the header
        len = len.saturating_add(self.header.consensus_encode(writer)?);

        // Encode the number of transactions
        len = len.saturating_add((self.transactions.len() as u64).consensus_encode(writer)?);

        // Encode each transaction
        for tx in &self.transactions {
            len = len.saturating_add(tx.consensus_encode(writer)?);
        }

        // Only encode witness_root if it exists
        if let Some(ref witness_root) = self.witness_root {
            len = len.saturating_add(witness_root.consensus_encode(writer)?);
        }

        Ok(len)
    }
}

#[allow(clippy::cast_possible_truncation, reason = "It will fit.")]
impl<H: Header> Decodable for Block<H> {
    fn consensus_decode<R: Read + ?Sized>(reader: &mut R) -> Result<Self, EncodeDecodeError> {
        // Decode the header
        let header = H::consensus_decode(reader)?;

        // Decode the number of transactions
        let tx_count: u64 = Decodable::consensus_decode(reader)?;

        // Decode each transaction
        let tx_count_usize = usize::try_from(tx_count).unwrap_or(0);
        let mut transactions = Vec::with_capacity(tx_count_usize);
        for _ in 0..tx_count {
            transactions.push(Transaction::consensus_decode(reader)?);
        }

        // Try to decode witness_root - if we're at the end of the data, this will fail,
        // and we'll just set it to None
        let witness_root = WitnessMerkleNode::consensus_decode(reader).ok();

        Ok(Block {
            header,
            transactions,
            witness_root,
        })
    }
}
