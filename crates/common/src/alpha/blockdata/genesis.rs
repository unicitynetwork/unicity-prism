//! Genesis block information for the Unicity network.

use bitcoin::{
    BlockHash as BitcoinBlockHash, CompactTarget, TxMerkleNode,
    block::{Header as InnerHeader, Version},
};
use serde::{Deserialize, Serialize};

use crate::alpha::{
    blockdata::block::{BitcoinHeader, Block, BlockHash},
    hashes::Hash,
    network::Network,
};

/// Genesis block information for different networks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisInfo {
    /// The hash of the genesis block.
    pub hash: BlockHash,
    /// The merkle root of the genesis block.
    pub merkle_root: BlockHash,
    /// The timestamp of the genesis block.
    pub timestamp: u32,
    /// The nonce of the genesis block.
    pub nonce: u32,
    /// The bits (difficulty) of the genesis block.
    pub bits: u32,
    /// The version of the genesis block.
    pub version: i32,
}

impl GenesisInfo {
    /// Returns the genesis block information for the specified network.
    ///
    /// # Arguments
    ///
    /// * `network` - The network type (mainnet, testnet, regtest)
    ///
    /// # Returns
    ///
    /// * `GenesisInfo` - The genesis block information for the specified
    ///   network
    pub fn for_network(network: Network) -> Self {
        match network {
            Network::Mainnet => Self::mainnet(),
            Network::Testnet => Self::testnet(),
            Network::Regtest => Self::regtest(),
        }
    }

    /// Returns the genesis block information for the mainnet network.
    pub fn mainnet() -> Self {
        Self {
            hash: BlockHash::from_byte_array([
                0x00, 0x00, 0x00, 0x0c, 0xd1, 0x59, 0x48, 0x2c, 0x96, 0x63, 0xa5, 0x0e, 0x6a, 0x23,
                0xa6, 0x31, 0x55, 0xf9, 0x47, 0x73, 0x84, 0x84, 0x34, 0x73, 0xb7, 0x84, 0x44, 0x9b,
                0x89, 0x75, 0x69, 0xbf,
            ]),
            merkle_root: BlockHash::from_byte_array([
                0xc6, 0x1f, 0x90, 0x03, 0x73, 0x5f, 0x01, 0xc7, 0x7c, 0x4a, 0x8b, 0x35, 0x54, 0xb8,
                0x6b, 0x8b, 0xda, 0x7c, 0xe1, 0xf3, 0x85, 0x4f, 0x1e, 0x65, 0x7a, 0xbf, 0xad, 0x6f,
                0x49, 0x46, 0x26, 0x14,
            ]),
            timestamp: 1718524492,
            nonce: 40358186,
            bits: 0x1d0fffff,
            version: 1,
        }
    }

    /// Returns the genesis block information for the testnet network.
    pub fn testnet() -> Self {
        Self {
            hash: BlockHash::from_byte_array([
                0x00, 0x00, 0x00, 0x0c, 0xd1, 0x59, 0x48, 0x2c, 0x96, 0x63, 0xa5, 0x0e, 0x6a, 0x23,
                0xa6, 0x31, 0x55, 0xf9, 0x47, 0x73, 0x84, 0x84, 0x34, 0x73, 0xb7, 0x84, 0x44, 0x9b,
                0x89, 0x75, 0x69, 0xbf,
            ]),
            merkle_root: BlockHash::from_byte_array([
                0xc6, 0x1f, 0x90, 0x03, 0x73, 0x5f, 0x01, 0xc7, 0x7c, 0x4a, 0x8b, 0x35, 0x54, 0xb8,
                0x6b, 0x8b, 0xda, 0x7c, 0xe1, 0xf3, 0x85, 0x4f, 0x1e, 0x65, 0x7a, 0xbf, 0xad, 0x6f,
                0x49, 0x46, 0x26, 0x14,
            ]),
            timestamp: 1718524492,
            nonce: 40358186,
            bits: 0x1d0fffff,
            version: 1,
        }
    }

    /// Returns the genesis block information for the regtest network.
    pub fn regtest() -> Self {
        Self {
            hash: BlockHash::from_byte_array([
                0x0f, 0x91, 0x88, 0xf1, 0x3c, 0xb7, 0xb2, 0xc7, 0x1f, 0x2a, 0x33, 0x5e, 0x3a, 0x4f,
                0xc3, 0x28, 0xbf, 0x5b, 0xeb, 0x43, 0x60, 0x12, 0xaf, 0xca, 0x59, 0x0b, 0x1a, 0x11,
                0x46, 0x6e, 0x22, 0x06,
            ]),
            merkle_root: BlockHash::from_byte_array([
                0x4a, 0x5e, 0x1e, 0x4b, 0xaa, 0xb8, 0x9f, 0x3a, 0x32, 0x51, 0x8a, 0x88, 0xc3, 0x1b,
                0xc8, 0x7f, 0x61, 0x8f, 0x76, 0x67, 0x3e, 0x2c, 0xc7, 0x7a, 0xb2, 0x12, 0x7b, 0x7a,
                0xfd, 0xed, 0xa3, 0x3b,
            ]),
            timestamp: 1296688602,
            nonce: 2,
            bits: 0x207fffff,
            version: 1,
        }
    }

    /// Creates a BitcoinHeader from the genesis block information.
    ///
    /// # Returns
    ///
    /// * `BitcoinHeader` - A BitcoinHeader containing the genesis block
    ///   information
    pub fn to_bitcoin_header(&self) -> BitcoinHeader {
        let inner_header = InnerHeader {
            version: Version::from_consensus(self.version),
            prev_blockhash: BitcoinBlockHash::all_zeros(), // Genesis block has no previous block
            merkle_root: TxMerkleNode::from_byte_array(self.merkle_root.to_byte_array()),
            time: self.timestamp,
            bits: CompactTarget::from_consensus(self.bits),
            nonce: self.nonce,
        };
        BitcoinHeader::from(inner_header)
    }

    /// Creates a full Block from the genesis block information.
    ///
    /// # Returns
    ///
    /// * `BitcoinBlock` - A Block containing the genesis block header and
    ///   transactions
    pub fn to_block(&self) -> Block<BitcoinHeader> {
        let header = self.to_bitcoin_header();
        // Genesis blocks typically have a single coinbase transaction
        // For now, we'll create an empty transaction list as the exact transaction
        // format should be determined by the specific network requirements
        let transactions = Vec::new();
        Block::new(header, transactions, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alpha::blockdata::block::BitcoinBlock;

    #[test]
    fn test_genesis_info() {
        let mainnet_genesis = GenesisInfo::mainnet();
        assert_eq!(
            mainnet_genesis.hash.to_string(),
            "bf6975899b4484b7733484847347f95531a6236a0ea563962c4859d10c000000"
        );
        assert_eq!(
            mainnet_genesis.merkle_root.to_string(),
            "142646496fadbf7a651e4f85f3e17cda8b6bb854358b4a7cc7015f7303901fc6"
        );
        assert_eq!(mainnet_genesis.timestamp, 1718524492);
        assert_eq!(mainnet_genesis.nonce, 40358186);
        assert_eq!(mainnet_genesis.bits, 0x1d0fffff);
        assert_eq!(mainnet_genesis.version, 1);
    }

    #[test]
    fn test_genesis_to_bitcoin_header() {
        let mainnet_genesis = GenesisInfo::mainnet();
        let header = mainnet_genesis.to_bitcoin_header();

        // Verify header fields match the genesis info
        assert_eq!(header.0.version.to_consensus(), 1);
        assert_eq!(header.0.prev_blockhash, BlockHash::all_zeros());
        assert_eq!(
            header.0.merkle_root.to_byte_array(),
            mainnet_genesis.merkle_root.to_byte_array()
        );
        assert_eq!(header.0.time, mainnet_genesis.timestamp);
        assert_eq!(header.0.bits.to_consensus(), mainnet_genesis.bits);
        assert_eq!(header.0.nonce, mainnet_genesis.nonce);
    }

    #[test]
    fn test_genesis_to_block() {
        let mainnet_genesis = GenesisInfo::mainnet();
        let block: BitcoinBlock = mainnet_genesis.to_block();

        // Verify block header matches the genesis info
        assert_eq!(block.header().0.version.to_consensus(), 1);
        assert_eq!(block.header().0.prev_blockhash, BlockHash::all_zeros());
        assert_eq!(
            block.header().0.merkle_root.to_byte_array(),
            mainnet_genesis.merkle_root.to_byte_array()
        );
        assert_eq!(block.header().0.time, mainnet_genesis.timestamp);
        assert_eq!(block.header().0.bits.to_consensus(), mainnet_genesis.bits);
        assert_eq!(block.header().0.nonce, mainnet_genesis.nonce);

        // Verify the block has no transactions (as expected for a basic genesis block)
        assert_eq!(block.transaction_count(), 0);
    }

    #[test]
    fn test_genesis_for_network() {
        let mainnet_genesis = GenesisInfo::for_network(Network::Mainnet);
        let testnet_genesis = GenesisInfo::for_network(Network::Testnet);
        let regtest_genesis = GenesisInfo::for_network(Network::Regtest);

        // Mainnet and testnet should have the same values currently
        assert_eq!(mainnet_genesis.hash, testnet_genesis.hash);
        assert_eq!(mainnet_genesis.merkle_root, testnet_genesis.merkle_root);
        assert_eq!(mainnet_genesis.timestamp, testnet_genesis.timestamp);

        // Regtest should have different values
        assert_ne!(mainnet_genesis.hash, regtest_genesis.hash);
        assert_ne!(mainnet_genesis.merkle_root, regtest_genesis.merkle_root);
        assert_ne!(mainnet_genesis.timestamp, regtest_genesis.timestamp);

        // Test that each can be converted to a block
        let _mainnet_block: BitcoinBlock = mainnet_genesis.to_block();
        let _testnet_block: BitcoinBlock = testnet_genesis.to_block();
        let _regtest_block: BitcoinBlock = regtest_genesis.to_block();
    }
}
