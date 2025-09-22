use crate::p2p::Magic;
use bitcoin::constants::ChainHash;
use bitcoin::network::UnknownChainHashError;
use thiserror::Error;

#[derive(Clone, Debug, Error)]
pub enum ChainTypeError {
    #[error("Invalid chain type: {0}")]
    InvalidChainType(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Network {
    /// Mainnet Unicity network.
    Mainnet,
    /// Testnet Unicity network.
    Testnet,
    /// Regtest Unicity network.
    Regtest,
}

impl Network {
    pub fn from_magic(magic: Magic) -> Option<Network> {
        Network::try_from(magic).ok()
    }

    pub fn magic(self) -> Magic {
        Magic::from(self)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Network::Mainnet => "alpha",
            Network::Testnet => "alphatestnet",
            Network::Regtest => "alpharegtest",
        }
    }
}

impl TryFrom<ChainHash> for Network {
    type Error = UnknownChainHashError;

    fn try_from(chain_hash: ChainHash) -> Result<Self, Self::Error> {
        todo!()
    }
}
