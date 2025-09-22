use crate::consensus::{Decodable, Encodable};
use crate::io::{Error, Read, Write};
use crate::network::Network;
use crate::params::Params;
pub use bitcoin::p2p::ServiceFlags;

/// Network magic bytes to identify the cryptocurrency network the message was intended for.
#[derive(Debug, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct Magic([u8; 4]);

impl Magic {
    /// Unicity main network magic bytes.
    pub const MAINNET: Self = Self([0xd9, 0xb4, 0xbe, 0xf9]);
    /// Unicity test network magic bytes.
    pub const TESTNET: Self = Self([0x0B, 0x11, 0x09, 0x07]);
    /// Unicity regression test network magic bytes.
    pub const REGTEST: Self = Self([0xc9, 0xaf, 0xae, 0xe9]);

    pub fn to_bytes(&self) -> [u8; 4] {
        self.0
    }

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
        Ok(hex::encode(self.0).fmt(f)?)
    }
}

impl Encodable for Magic {
    fn consensus_encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, Error> {
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
