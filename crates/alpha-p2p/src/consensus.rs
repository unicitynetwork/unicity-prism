mod params;

pub use encode::{Decodable, Encodable, Error as EncodeDecodeError, MAX_VEC_SIZE};
pub use params::Params;

pub mod encode {
    pub use bitcoin::consensus::encode::{Decodable, Encodable, Error, MAX_VEC_SIZE};
}
