use std::str::FromStr;

use bitcoin::constants::ChainHash;
use thiserror::Error;

use crate::alpha::{consensus::Params, p2p::Magic};

/// Errors that can occur when parsing a chain type.
#[derive(Clone, Debug, Error)]
pub enum ChainTypeError {
    /// The provided chain type string is invalid.
    #[error("Invalid chain type: {0}")]
    InvalidChainType(String),
}

/// Error for unknown chain hash.
#[derive(Clone, Copy, Debug, Error)]
#[error("Unknown chain hash: {0}")]
pub struct UnknownChainHashError(ChainHash);

/// The Unicity network variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Network {
    /// Mainnet Unicity network.
    Mainnet,
    /// Testnet Unicity network.
    Testnet,
    /// Regtest Unicity network.
    Regtest,
}

impl Network {
    /// Converts a magic value to the corresponding Network variant.
    ///
    /// # Arguments
    ///
    /// * `magic` - The magic bytes to convert
    ///
    /// # Returns
    ///
    /// * `Some(Network)` - The corresponding network if the magic is recognized
    /// * `None` - If the magic bytes don't match any known network
    pub fn from_magic(magic: Magic) -> Option<Network> {
        Network::try_from(magic).ok()
    }

    /// Returns the magic bytes for this network.
    ///
    /// # Returns
    ///
    /// The magic bytes corresponding to this network
    pub fn magic(self) -> Magic {
        Magic::from(self)
    }

    /// Returns the string representation of this network.
    ///
    /// # Returns
    ///
    /// A string slice representing the network name
    pub fn as_str(&self) -> &'static str {
        // NOTE: Might be fine to simply use mainnet, testnet, regtest here.
        match self {
            Network::Mainnet => "alpha",
            Network::Testnet => "alphatestnet",
            Network::Regtest => "alpharegtest",
        }
    }
}

impl Network {
    /// Returns the consensus parameters for this network.
    ///
    /// # Returns
    ///
    /// * `Params` - The consensus parameters for this network
    pub fn consensus_params(self) -> Params {
        match self {
            Network::Mainnet => Params::MAINNET,
            Network::Testnet => Params::TESTNET,
            Network::Regtest => Params::REGTEST,
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
