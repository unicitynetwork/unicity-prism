mod params;

pub use bitcoin::consensus::encode::{
    Decodable, Encodable, Error as EncodeDecodeError, MAX_VEC_SIZE, VarInt,
};
pub use params::Params;
pub use unicity_prism_derive::ConsensusCodec;
