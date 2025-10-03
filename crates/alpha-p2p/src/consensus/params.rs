use crate::{network::Network, pow::Target};

/// ASERT anchor parameters.
#[derive(Debug, Clone, Copy)]
pub struct ASERTAnchorParams {
    /// Anchor block height.
    pub height: u32,
    /// Anchor block bits.
    pub bits: u32,
    /// Anchor block previous block timestamp.
    pub prev_block_time: u64,
}

/// Consensus parameters for different networks.
#[derive(Debug, Clone, Copy)]
pub struct Params {
    /// Network for which these parameters are defined.
    pub network: Network,
    /// The block height which BIP34 becomes active.
    pub bip34_height: u32,
    /// The block height which BIP65 becomes active.
    pub bip65_height: u32,
    /// The block height which BIP66 becomes active.
    pub bip66_height: u32,
    /// The block height which RandomX becomes active.
    pub randomx_height: u32,
    /// The block height which RandomX becomes enforced (non-RandomX blocks are
    /// rejected).
    pub randomx_enforcement_height: u32,
    /// The multiplier for RandomX difficulty adjustment when SHA256D switches
    /// to RandomX.
    pub randomx_difficulty_multiplier: u32,
    /// Whether the PoW algorithm is RandomX (true) or SHA256D (false).
    pub pow_randomx: bool,
    /// The duration of each RandomX epoch, in blocks. If 0, then there are no
    /// epochs.
    pub randomx_epoch_duration: u32,
    /// The block height which ASERT becomes active.
    pub asert_activiation_height: u32,
    /// The ASERT anchor parameters, if ASERT is used.
    pub asert_anchor_params: Option<ASERTAnchorParams>,
    /// Whether Unicity is enabled (true) or not (false).
    pub unicity_enabled: bool,
    /// Minimum blocks including miner confirmation of the total of 2016 blocks
    /// in a retargeting period, (nPowTargetTimespan / nPowTargetSpacing)
    /// which is also used for BIP9 deployments. Examples: 1916 for 95%,
    /// 1512 for testchains.
    pub rule_change_activiation_threshold: u32,
    /// Number of blocks with the same set of rules.
    pub miner_confirmation_window: u32,
    /// The maximum attainable target value for these params.
    pub max_attainable_target: Target,
    /// Expected amount of time to mine one block.
    pub pow_target_spacing: u64,
    /// Difficult recalculation interval.
    pub pow_target_timespan: u64,
    /// Determines whether minimal difficult may be used for blocks or not.
    pub allow_min_difficulty_blocks: bool,
    /// Determines whether retargeting is disabled for this network or not.
    pub no_pow_retargeting: bool,
}

impl Params {
    /// Consensus parameters for the Unicity mainnet network.
    pub const MAINNET: Self = Self {
        network: Network::Mainnet,
        bip34_height: 70_228, // 953181e5afbf5a0052bdf405d6a23360ba6afa9c4a5bb2eda4a9b8f5de52fdcc
        bip65_height: 70_228, // 953181e5afbf5a0052bdf405d6a23360ba6afa9c4a5bb2eda4a9b8f5de52fdcc
        bip66_height: 70_228, // 953181e5afbf5a0052bdf405d6a23360ba6afa9c4a5bb2eda4a9b8f5de52fdcc
        randomx_height: 70_228, // 953181e5afbf5a0052bdf405d6a23360ba6afa9c4a5bb2eda4a9b8f5de52fdcc
        randomx_enforcement_height: 303_271, /* 73bdb33d786215ca63d5f9aa8a81ff5dabb0bc87e3c49cef5e6f1139983e33d8 */
        randomx_difficulty_multiplier: 100_000,
        pow_randomx: true,
        randomx_epoch_duration: 7 * 24 * 60 * 60, // 1 week
        asert_activiation_height: 70_240, /* 35ab17718c910ffbd7624b54ec23bafa82430532904cd1998e74898928014308 */
        asert_anchor_params: Some(ASERTAnchorParams {
            height: 70_232, // c3c990c429d3588c929681453b4a7557ce121b1de0d31044e713eec9b8fa3959
            bits: 0x1e1d7cb5,
            prev_block_time: 1_725_980_278,
        }),
        unicity_enabled: true,
        rule_change_activiation_threshold: 1815, // 90% of 2016
        miner_confirmation_window: 2016,         // nPowTargetTimespan / nPowTargetSpacing
        max_attainable_target: Target::mainnet_max_target(),
        pow_target_spacing: 2 * 60,                 // 2 minutes
        pow_target_timespan: 14 * 24 * 60 * 60 / 5, // two weeks / 5
        allow_min_difficulty_blocks: false,
        no_pow_retargeting: false,
    };
    /// Consensus parameters for the Unicity regtest network.
    pub const REGTEST: Self = Self {
        network: Network::Regtest,
        bip34_height: 1,               // Always active
        bip65_height: 1,               // Always active
        bip66_height: 1,               // Always active
        randomx_height: 1,             // Always active
        randomx_enforcement_height: 1, // Always active
        randomx_difficulty_multiplier: 100_000,
        pow_randomx: true,
        randomx_epoch_duration: 7 * 24 * 60 * 60, // 1 week
        asert_activiation_height: 1,              // Always active
        asert_anchor_params: None,                // Not needed for regtest
        unicity_enabled: true,
        rule_change_activiation_threshold: 108, // 75% of 144
        miner_confirmation_window: 144,         // nPowTargetTimespan / nPowTargetSpacing
        max_attainable_target: Target::regtest_max_target(),
        pow_target_spacing: 2 * 60,                 // 2 minutes
        pow_target_timespan: 14 * 24 * 60 * 60 / 5, // two weeks / 5
        allow_min_difficulty_blocks: true,
        no_pow_retargeting: true,
    };
    /// Consensus parameters for the Unicity testnet network.
    pub const TESTNET: Self = Self {
        network: Network::Testnet,
        bip34_height: 1,               // Always active
        bip65_height: 1,               // Always active
        bip66_height: 1,               // Always active
        randomx_height: 1,             // Always active
        randomx_enforcement_height: 1, // Always active
        randomx_difficulty_multiplier: 100_000,
        pow_randomx: true,
        randomx_epoch_duration: 7 * 24 * 60 * 60, // 1 week
        asert_activiation_height: 1,              // Always active
        asert_anchor_params: None,                // Not needed for testnet
        unicity_enabled: true,
        rule_change_activiation_threshold: 1512, // 75% of 2016
        miner_confirmation_window: 2016,         // nPowTargetTimespan / nPowTargetSpacing
        max_attainable_target: Target::mainnet_max_target(),
        pow_target_spacing: 2 * 60,                 // 2 minutes
        pow_target_timespan: 14 * 24 * 60 * 60 / 5, // two weeks / 5
        allow_min_difficulty_blocks: true,
        no_pow_retargeting: false,
    };
}
