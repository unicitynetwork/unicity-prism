use crate::p2p::Magic;
use bitcoin::constants::ChainHash;
use bitcoin::network::UnknownChainHashError;
use std::str::FromStr;
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
        // NOTE: Might be fine to simply use mainnet, testnet, regtest here.
        match self {
            Network::Mainnet => "alpha",
            Network::Testnet => "alphatestnet",
            Network::Regtest => "alpharegtest",
        }
    }
}

impl FromStr for Network {
    type Err = ChainTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Network::try_from(s)
    }
}

impl TryFrom<&str> for Network {
    type Error = ChainTypeError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "alpha" | "mainnet" => Ok(Network::Mainnet),
            "alphatestnet" | "testnet" => Ok(Network::Testnet),
            "alpharegtest" | "regtest" => Ok(Network::Regtest),
            other => Err(ChainTypeError::InvalidChainType(other.to_string())),
        }
    }
}

impl TryFrom<String> for Network {
    type Error = ChainTypeError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Network::try_from(s.as_str())
    }
}

impl TryFrom<ChainHash> for Network {
    type Error = UnknownChainHashError;

    fn try_from(chain_hash: ChainHash) -> Result<Self, Self::Error> {
        todo!()
    }
}
