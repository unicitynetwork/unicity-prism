use crate::client::peer::Peer;
use crate::Network;
use std::path::PathBuf;

mod message;
mod peer;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Config {
    pub network: Network,
    pub max_connections: u64,
    pub data_dir: PathBuf,
    pub user_agent: String,
    pub disabled_peer_discovery: bool,
    pub disable_dns_seeds: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    config: Config,
    peers: Vec<Peer>,
}
