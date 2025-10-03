//! Block response message types for the P2P protocol.
//!
//! This module contains the different block response message implementations,
//! including both standard blocks and witness blocks.
//!
//! # Block Types
//!
//! The P2P protocol supports two types of block responses:
//! - `StandardBlock`: Contains full block data without witness information
//! - `WitnessBlock`: Contains full block data with witness information for transaction verification
//!
//! # Usage
//!
//! Block response messages are used to send block data from peers in response to
//! `getblocks` or `getdata` requests. The `Block` trait provides a unified interface
//! for handling both standard and witness blocks.
//!
//! # Consensus Encoding
//!
//! Both `StandardBlock` and `WitnessBlock` implement the `ConsensusCodec` derive,
//! allowing them to be encoded and decoded according to Bitcoin's consensus rules.
//!
//! # Examples
//!
//! ```rust
//! use alpha_p2p::client::message::response::block::{StandardBlock, WitnessBlock};
//! use alpha_p2p::client::message::response::block::Block;
//!
//! // Create a standard block
//! let standard_block = StandardBlock::new(header, transactions);
//!
//! // Create a witness block
//! let witness_block = WitnessBlock::new(header, transactions, witness_root);
//!
//! // Use the unified interface
//! let block_header = standard_block.header();
//! let block_transactions = standard_block.transactions();
//!
//! // Both types implement the Block trait
//! let header1: &Header = standard_block.header();
//! let header2: &Header = witness_block.header();
//! ```

use crate::blockdata::block::{Header, WitnessMerkleNode};
use crate::blockdata::transaction::Transaction;
use alpha_p2p_derive::ConsensusCodec;

/// Trait for block response messages to allow type-safe handling of both witness and non-witness blocks.
pub trait Block<H: Header>: Send + Sync {
    /// Returns the block header.
    fn header(&self) -> &H;

    /// Returns the list of transactions in the block.
    fn transactions(&self) -> &[Transaction];
}

/// Represents a standard block response message in the P2P protocol.
///
/// A `StandardBlock` response contains the full block data, including:
/// - The block header
/// - A list of transactions contained in the block
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, ConsensusCodec)]
pub struct StandardBlock<H: Header> {
    /// The block header containing metadata like timestamp and previous block hash
    pub header: H,

    /// List of transactions contained in the block
    pub transactions: Vec<Transaction>,
}

#[allow(dead_code)]
impl<H: Header> StandardBlock<H> {
    /// Creates a new `StandardBlock` response message with the specified header and transactions.
    ///
    /// # Arguments
    ///
    /// * `header` - The block header.
    /// * `transactions` - A vector of transactions contained in the block.
    ///
    /// # Returns
    ///
    /// * `StandardBlock` - A new instance of the StandardBlock response message.
    pub fn new(header: H, transactions: Vec<Transaction>) -> Self {
        Self {
            header,
            transactions,
        }
    }

    /// Returns the block header.
    ///
    /// # Returns
    ///
    /// * `&Header` - A reference to the block header.
    pub fn header(&self) -> &H {
        &self.header
    }

    /// Returns the list of transactions in the block.
    ///
    /// # Returns
    ///
    /// * `&[Transaction]` - A slice of the transactions in the block.
    pub fn transactions(&self) -> &[Transaction] {
        &self.transactions
    }
}

impl<H: Header> Block<H> for StandardBlock<H> {
    /// Returns the block header.
    fn header(&self) -> &H {
        &self.header
    }

    /// Returns the list of transactions in the block.
    fn transactions(&self) -> &[Transaction] {
        &self.transactions
    }
}

/// Represents a witness block response message in the P2P protocol.
///
/// A `WitnessBlock` response contains the full block data with witness information,
/// including:
/// - The block header
/// - A list of transactions contained in the block  
/// - Witness root for transaction witness data verification
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, ConsensusCodec)]
#[allow(dead_code)]
pub struct WitnessBlock<H: Header> {
    /// The block header containing metadata like timestamp and previous block hash
    pub header: H,

    /// List of transactions contained in the block
    pub transactions: Vec<Transaction>,

    /// Witness root for transaction witness data verification
    pub witness_root: WitnessMerkleNode,
}

#[allow(dead_code)]
impl<H: Header> WitnessBlock<H> {
    /// Creates a new `WitnessBlock` response message with the specified header, transactions and witness root.
    ///
    /// # Arguments
    ///
    /// * `header` - The block header.
    /// * `transactions` - A vector of transactions contained in the block.
    /// * `witness_root` - The witness root for transaction witness data verification.
    ///
    /// # Returns
    ///
    /// * `WitnessBlock` - A new instance of the WitnessBlock response message.
    pub fn new(header: H, transactions: Vec<Transaction>, witness_root: WitnessMerkleNode) -> Self {
        Self {
            header,
            transactions,
            witness_root,
        }
    }

    /// Returns the witness root.
    ///
    /// # Returns
    ///
    /// * `&WitnessMerkleNode` - A reference to the witness root.
    pub fn witness_root(&self) -> &WitnessMerkleNode {
        &self.witness_root
    }
}

impl<H: Header> Block<H> for WitnessBlock<H> {
    /// Returns the block header.
    fn header(&self) -> &H {
        &self.header
    }

    /// Returns the list of transactions in the block.
    fn transactions(&self) -> &[Transaction] {
        &self.transactions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockdata::block::{BitcoinHeader, WitnessMerkleNode};
    use crate::blockdata::transaction::Transaction;
    use crate::consensus::{Decodable, Encodable};
    use crate::hashes::Hash;
    use bitcoin::block::Version;
    pub use bitcoin::blockdata::block::Header as InnerBitcoinHeader;
    use bitcoin::pow::CompactTarget;
    use bitcoin::{BlockHash, TxMerkleNode};

    /// Create a minimal test transaction for use in tests
    fn create_test_transaction() -> Transaction {
        // Create a minimal valid transaction using the bitcoin crate types
        use crate::blockdata::transaction::Version;
        use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, locktime::absolute};

        let txin = TxIn {
            previous_output: bitcoin::OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: bitcoin::Witness::default(),
        };

        let txout = TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::new(),
        };

        Transaction {
            version: Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            input: vec![txin],
            output: vec![txout],
        }
    }

    fn create_test_header() -> BitcoinHeader {
        InnerBitcoinHeader {
            version: Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 0,
            bits: CompactTarget::from_consensus(0x1d00ffff), // Use the compact bits value directly (Bitcoin genesis block difficulty)
            nonce: 1,
        }
        .into()
    }

    fn create_test_header_with_nonce(nonce: u32) -> BitcoinHeader {
        InnerBitcoinHeader {
            version: Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 0,
            bits: CompactTarget::from_consensus(0x1d00ffff), // Use the compact bits value directly (Bitcoin genesis block difficulty)
            nonce,
        }
        .into()
    }

    #[test]
    fn test_standard_block_new() {
        let header = create_test_header();
        let transactions = vec![create_test_transaction()];

        let block = StandardBlock::new(header, transactions.clone());

        assert_eq!(block.header(), &header);
        assert_eq!(block.transactions(), transactions.as_slice());
    }

    #[test]
    fn test_standard_block_header() {
        let header = create_test_header();
        let transactions = vec![create_test_transaction()];

        let block = StandardBlock::new(header, transactions);
        assert_eq!(block.header(), &header);
    }

    #[test]
    fn test_standard_block_transactions() {
        let header = create_test_header();
        let transactions = vec![create_test_transaction(), create_test_transaction()];

        let block = StandardBlock::new(header, transactions.clone());
        assert_eq!(block.transactions(), transactions.as_slice());
    }

    #[test]
    fn test_witness_block_new() {
        let header = create_test_header();
        let transactions = vec![create_test_transaction()];
        let witness_root = WitnessMerkleNode::all_zeros();

        let block = WitnessBlock::new(header, transactions.clone(), witness_root);

        assert_eq!(block.header(), &header);
        assert_eq!(block.transactions(), transactions.as_slice());
        assert_eq!(block.witness_root(), &witness_root);
    }

    #[test]
    fn test_witness_block_header() {
        let header = create_test_header();
        let transactions = vec![create_test_transaction()];
        let witness_root = WitnessMerkleNode::all_zeros();

        let block = WitnessBlock::new(header, transactions, witness_root);
        assert_eq!(block.header(), &header);
    }

    #[test]
    fn test_witness_block_transactions() {
        let header = create_test_header();
        let transactions = vec![create_test_transaction(), create_test_transaction()];
        let witness_root = WitnessMerkleNode::all_zeros();

        let block = WitnessBlock::new(header, transactions.clone(), witness_root);
        assert_eq!(block.transactions(), transactions.as_slice());
    }

    #[test]
    fn test_witness_block_witness_root() {
        let header = create_test_header();
        let transactions = vec![create_test_transaction()];
        let witness_root = WitnessMerkleNode::all_zeros();

        let block = WitnessBlock::new(header, transactions, witness_root);
        assert_eq!(block.witness_root(), &witness_root);
    }

    #[test]
    fn test_block_trait_implementation() {
        let header = create_test_header();
        let transactions = vec![create_test_transaction()];
        let witness_root = WitnessMerkleNode::all_zeros();

        // Test StandardBlock implements Block trait
        let standard_block = StandardBlock::new(header, transactions.clone());
        assert_eq!(standard_block.header(), &header);
        assert_eq!(standard_block.transactions(), transactions.as_slice());

        // Test WitnessBlock implements Block trait
        let witness_block = WitnessBlock::new(header, transactions.clone(), witness_root);
        assert_eq!(witness_block.header(), &header);
        assert_eq!(witness_block.transactions(), transactions.as_slice());
    }

    #[test]
    fn test_standard_block_round_trip() {
        let header = create_test_header();
        let transactions = vec![create_test_transaction()];

        let original = StandardBlock::new(header, transactions);

        // Encode
        let mut encoded = Vec::new();
        original.consensus_encode(&mut encoded).unwrap();

        // Decode
        let mut cursor = std::io::Cursor::new(&encoded);
        let decoded = StandardBlock::consensus_decode(&mut cursor).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_witness_block_round_trip() {
        let header = create_test_header();
        let transactions = vec![create_test_transaction()];
        let witness_root = WitnessMerkleNode::all_zeros();

        let original = WitnessBlock::new(header, transactions, witness_root);

        // Encode
        let mut encoded = Vec::new();
        original.consensus_encode(&mut encoded).unwrap();

        // Decode
        let mut cursor = std::io::Cursor::new(&encoded);
        let decoded = WitnessBlock::consensus_decode(&mut cursor).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_standard_block_equality() {
        let header1 = create_test_header_with_nonce(1);
        let header2 = create_test_header_with_nonce(2);
        let transactions = vec![create_test_transaction()];

        let block1 = StandardBlock::new(header1, transactions.clone());
        let block2 = StandardBlock::new(header2, transactions);

        // Different headers should not be equal
        assert_ne!(block1, block2);
    }

    #[test]
    fn test_witness_block_equality() {
        let header1 = create_test_header_with_nonce(1);
        let header2 = create_test_header_with_nonce(2);
        let transactions = vec![create_test_transaction()];
        let witness_root1 = WitnessMerkleNode::all_zeros();
        let witness_root2 = WitnessMerkleNode::all_zeros();

        let block1 = WitnessBlock::new(header1, transactions.clone(), witness_root1);
        let block2 = WitnessBlock::new(header2, transactions, witness_root2);

        // Different headers and witness roots should not be equal
        assert_ne!(block1, block2);
    }
}
