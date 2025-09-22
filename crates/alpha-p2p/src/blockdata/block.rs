use crate::blockdata::transaction::Transaction;
use crate::consensus::{self, Decodable, Encodable, EncodeDecodeError, Params};
use crate::hashes::{hash_newtype, sha256d, Hash};
use crate::io::{IoError, Read, Write};
use crate::pow::{CompactTarget, Target};
pub use bitcoin::block::{BlockHash, TxMerkleNode, Version, WitnessMerkleNode};
use serde::{Deserialize, Serialize};

/// Denotes in the block header if it is a RandomX block, or not.
const RX_VERSIONBIT: i32 = 0x02;

hash_newtype! {
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

#[allow(
    clippy::arithmetic_side_effects,
    reason = "It can't possibly overflow, as the values are expected to be small."
)]
impl Encodable for Header {
    fn consensus_encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, IoError> {
        let mut len = 0;
        len += self.version.consensus_encode(writer)?;
        len += self.prev_blockhash.consensus_encode(writer)?;
        len += self.merkle_root.consensus_encode(writer)?;
        len += self.timestamp.consensus_encode(writer)?;
        len += self.bits.consensus_encode(writer)?;
        len += self.nonce.consensus_encode(writer)?;
        len += self.randomx_hash.consensus_encode(writer)?;
        Ok(len)
    }
}

impl Decodable for Header {
    #[inline]
    fn consensus_decode_from_finite_reader<R: Read + ?Sized>(
        r: &mut R,
    ) -> Result<Header, EncodeDecodeError> {
        Ok(Header {
            version: Decodable::consensus_decode_from_finite_reader(r)?,
            prev_blockhash: Decodable::consensus_decode_from_finite_reader(r)?,
            merkle_root: Decodable::consensus_decode_from_finite_reader(r)?,
            timestamp: Decodable::consensus_decode_from_finite_reader(r)?,
            bits: Decodable::consensus_decode_from_finite_reader(r)?,
            nonce: Decodable::consensus_decode_from_finite_reader(r)?,
            randomx_hash: Decodable::consensus_decode_from_finite_reader(r)?,
        })
    }

    #[inline]
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Header, EncodeDecodeError> {
        let mut r = r.take(consensus::encode::MAX_VEC_SIZE as u64);
        Ok(Header {
            version: Decodable::consensus_decode(&mut r)?,
            prev_blockhash: Decodable::consensus_decode(&mut r)?,
            merkle_root: Decodable::consensus_decode(&mut r)?,
            timestamp: Decodable::consensus_decode(&mut r)?,
            bits: Decodable::consensus_decode(&mut r)?,
            nonce: Decodable::consensus_decode(&mut r)?,
            randomx_hash: Decodable::consensus_decode(&mut r)?,
        })
    }
}

impl Header {
    /// The number of bytes the block header contributes to the size of the block.
    pub const SIZE: usize = 4 + 32 + 32 + 4 + 4 + 4 + 32; // 112

    /// Return the block hash.
    pub fn block_hash(&self) -> BlockHash {
        let mut engine = BlockHash::engine();
        #[allow(clippy::expect_used, reason = "Expected inputs can't fail")]
        self.consensus_encode(&mut engine)
            .expect("Expected inputs can't fail");
        BlockHash::from_engine(engine)
    }

    /// Computes the target (range [0, T] inclusive) that a blockhash must land in to be valid.
    pub fn target(&self) -> Target {
        self.bits.into()
    }

    /// Computes the difficulty for mining.
    pub fn difficulty(&self, _params: impl AsRef<Params>) -> u128 {
        todo!()
        // self.target().difficulty(params)
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
