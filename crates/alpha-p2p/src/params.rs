use crate::blockdata::block::Block;

pub struct Params {
    message_start: [u8; 4],
    default_port: u16,
    seeds: Vec<String>,
    bech32_hrp: String,
    chain_type: ChainType,
    genesis: Block,
}
