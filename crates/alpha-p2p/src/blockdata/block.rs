pub use bitcoin::block::{BlockHash, TxMerkleNode, Version};
use bitcoin::consensus::Encodable;
use bitcoin::hashes::{hash_newtype, sha256d, Hash};
use bitcoin::io::{Error, Read, Write};
use bitcoin::{CompactTarget, Transaction, WitnessMerkleNode};
use serde::{Deserialize, Serialize};

/// Denotes in the block header if it is a RandomX block, or not.
const RX_VERSIONBIT: i32 = 0x02;

hash_newtype! {
    pub struct RandomXHash(sha256d::Hash);
}

impl bitcoin::consensus::Encodable for RandomXHash {
    fn consensus_encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, Error> {
        self.0.consensus_encode(writer)
    }
}

impl bitcoin::consensus::Decodable for RandomXHash {
    fn consensus_decode<R: Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        use bitcoin::hashes::Hash;
        Ok(Self::from_byte_array(
            <<RandomXHash as Hash>::Bytes>::consensus_decode(reader)?,
        ))
    }
}

/// Alpha block header.
///
/// Contains all the block's information except the actual transactions, but
/// including a root of a merkle tree committing to all transactions in the block.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Header {
    /// Block version, now repurposed for soft fork signalling.
    pub version: Version,
    /// Reference to the previous block in the chain.
    pub prev_blockhash: BlockHash,
    /// The root hash of the merkle tree of transactions in the block.
    pub merkle_root: TxMerkleNode,
    /// The timestamp of the block, as claimed by the miner.
    pub timestamp: u32,
    /// The target value below which the blockhash must lie.
    pub bits: CompactTarget,
    /// The nonce, selected to obtain a low enough blockhash.
    pub nonce: u32,
    /// The RandomX hash,
    pub randomx_hash: [u8; 32],
}

// TODO: Encoding implementation

impl Header {
    /// The number of bytes the block header contributes to the size of the block.
    pub const SIZE: usize = 4 + 32 + 32 + 4 + 4 + 4 + 32; // 112

    pub fn block_hash(&self) -> BlockHash {
        let mut engine = BlockHash::engine();
        self.consensus_encode(&mut engine)
            .expect("engines don't error");
        BlockHash::from_engine(engine)
    }

    pub fn difficulty(&self, params: impl AsRef<Params>) -> u128 {
        self.target().difficulty(params)
    }
}

#[derive(Clone, Debug)]
pub struct Block {
    /// The block header
    pub header: Header,
    /// List of transactions contained in the block
    pub transactions: Vec<Transaction>,
    /// Cached witness root, if it's been computed
    pub witness_root: Option<WitnessMerkleNode>,
}
