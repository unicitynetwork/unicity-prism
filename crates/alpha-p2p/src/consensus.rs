mod params;

pub use alpha_p2p_derive::ConsensusEncoding;
pub use encode::{Decodable, Encodable, Error as EncodeDecodeError, VarInt, MAX_VEC_SIZE};
pub use params::Params;

pub mod encode {
    pub use bitcoin::consensus::encode::{Decodable, Encodable, Error, VarInt, MAX_VEC_SIZE};
}
