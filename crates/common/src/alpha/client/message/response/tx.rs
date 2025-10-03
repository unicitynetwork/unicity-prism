//! Transaction response message types for the P2P protocol.
//!
//! This module contains the transaction response message implementation, which
//! is used to send complete transaction data from peers in response to
//! `getdata` requests.
//!
//! # Usage
//!
//! The `Tx` message is used to send full transaction data when a peer requests
//! it. This allows for complete transaction information to be transmitted over
//! the P2P network when needed.
//!
//! # Consensus Encoding
//!
//! The `Tx` struct manually implements `Encodable` and `Decodable` traits,
//! allowing it to be encoded and decoded according to Bitcoin's consensus
//! rules. The encoding simply delegates to the underlying `Transaction`
//! encoding.
//!
//! # Examples
//!
//! TODO: Add examples when the library is more mature.

use crate::alpha::{
    blockdata::transaction::Transaction,
    consensus::{Decodable, Encodable},
};

/// Represents a transaction response message in the P2P protocol.
///
/// A `Tx` response contains a complete transaction that was requested by a
/// peer.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Tx {
    /// The complete transaction data.
    pub transaction: Transaction,
}

impl Tx {
    /// Creates a new `Tx` response message with the specified transaction.
    ///
    /// # Arguments
    ///
    /// * `transaction` - The transaction to include in the response.
    ///
    /// # Returns
    ///
    /// * `Tx` - A new instance of the Tx response message.
    pub fn new(transaction: Transaction) -> Self {
        Self { transaction }
    }

    /// Returns the transaction in the response.
    ///
    /// # Returns
    ///
    /// * `&Transaction` - A reference to the transaction in the response.
    pub fn transaction(&self) -> &Transaction {
        &self.transaction
    }
}

impl Encodable for Tx {
    fn consensus_encode<W: crate::alpha::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<usize, crate::alpha::io::Error> {
        self.transaction.consensus_encode(writer)
    }
}

impl Decodable for Tx {
    fn consensus_decode<R: crate::alpha::io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, crate::alpha::consensus::EncodeDecodeError> {
        let transaction = Transaction::consensus_decode(reader)?;
        Ok(Tx { transaction })
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::consensus::{Decodable, Encodable};

    use super::*;
    use crate::alpha::blockdata::transaction::Transaction;

    /// Create a minimal test transaction for use in tests
    fn create_test_transaction() -> Transaction {
        use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, locktime::absolute};

        use crate::alpha::blockdata::transaction::Version;

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

    #[test]
    fn test_tx_new() {
        let transaction = create_test_transaction();

        let response = Tx::new(transaction.clone());

        assert_eq!(response.transaction(), &transaction);
    }

    #[test]
    fn test_tx_transaction_access() {
        let transaction = create_test_transaction();

        let response = Tx::new(transaction.clone());

        assert_eq!(response.transaction(), &transaction);
    }

    #[test]
    fn test_tx_round_trip() {
        let transaction = create_test_transaction();

        let original = Tx::new(transaction);

        // Encode
        let mut encoded = Vec::new();
        original.consensus_encode(&mut encoded).unwrap();

        // Decode
        let mut cursor = std::io::Cursor::new(&encoded);
        let decoded = Tx::consensus_decode(&mut cursor).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_tx_equality() {
        let transaction1 = create_test_transaction();
        let transaction2 = create_test_transaction();

        let response1 = Tx::new(transaction1);
        let response2 = Tx::new(transaction2);

        // Same transaction should be equal
        assert_eq!(response1, response2);
    }
}
