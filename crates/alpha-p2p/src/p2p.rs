pub(crate) mod address;
/// P2P protocol message types and functionality.
pub mod message;

pub use bitcoin::p2p::ServiceFlags;
use thiserror::Error;

use crate::{
    consensus::{Decodable, Encodable, Params},
    io::{Error as IoError, Read, Write},
    network::Network,
};

/// Network magic bytes to identify the cryptocurrency network the message was
/// intended for.
#[derive(Debug, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct Magic([u8; 4]);

impl Magic {
    /// Unicity main network magic bytes.
    pub const MAINNET: Self = Self([0xd9, 0xb4, 0xbe, 0xf9]);
    /// Unicity regression test network magic bytes.
    pub const REGTEST: Self = Self([0xc9, 0xaf, 0xae, 0xe9]);
    /// Unicity test network magic bytes.
    pub const TESTNET: Self = Self([0x0B, 0x11, 0x09, 0x07]);

    /// Returns the magic bytes as a 4-byte array.
    ///
    /// # Returns
    ///
    /// A 4-byte array containing the magic bytes
    pub fn to_bytes(&self) -> [u8; 4] {
        self.0
    }

    /// Creates a Magic instance from consensus parameters.
    ///
    /// # Arguments
    ///
    /// * `params` - The consensus parameters containing the network information
    ///
    /// # Returns
    ///
    /// A Magic instance corresponding to the network in the parameters
    pub fn from_params(params: impl AsRef<Params>) -> Self {
        params.as_ref().network.into()
    }
}

impl From<Network> for Magic {
    fn from(network: Network) -> Self {
        match network {
            Network::Mainnet => Magic::MAINNET,
            Network::Testnet => Magic::TESTNET,
            Network::Regtest => Magic::REGTEST,
        }
    }
}

impl std::fmt::Display for Magic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        hex::encode(self.0).fmt(f)
    }
}

impl Encodable for Magic {
    fn consensus_encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, IoError> {
        self.0.consensus_encode(writer)
    }
}

impl Decodable for Magic {
    fn consensus_decode<R: Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        Ok(Magic(Decodable::consensus_decode(reader)?))
    }
}

/// Errors that can occur when working with magic bytes.
#[derive(Debug, PartialEq, Clone, Copy, Error)]
pub enum MagicError {
    /// The magic bytes don't correspond to any known network.
    #[error("unknown network magic: {0}")]
    UnknownMagic(Magic),
}

impl TryFrom<Magic> for Network {
    type Error = MagicError;

    fn try_from(magic: Magic) -> Result<Self, Self::Error> {
        match magic {
            Magic::MAINNET => Ok(Network::Mainnet),
            Magic::TESTNET => Ok(Network::Testnet),
            Magic::REGTEST => Ok(Network::Regtest),
            _ => Err(MagicError::UnknownMagic(magic)),
        }
    }
}
