mod params;

pub use alpha_p2p_derive::ConsensusCodec;
pub use encode::{Decodable, Encodable, Error as EncodeDecodeError, MAX_VEC_SIZE, VarInt};
pub use params::Params;

pub mod encode {
    pub use bitcoin::consensus::encode::{Decodable, Encodable, Error, MAX_VEC_SIZE, VarInt};
}
