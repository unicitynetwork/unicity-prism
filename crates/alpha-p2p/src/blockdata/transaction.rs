#[derive(Clone, Debug)]
pub struct TransactionIn {
    prev_transaction_out: [u8; 32],
    script_sig: Vec<u8>,
    sequence: u32,
    script_witness: Option<Vec<Vec<u8>>>, // TODO: double check
}

#[derive(Clone, Debug)]
pub struct TransactionOut {
    value: u64,
    script_pubkey: Vec<u8>,
}

impl TransactionOut {
    pub fn new(value: u64, script_pubkey: Vec<u8>) -> Self {
        Self {
            value,
            script_pubkey,
        }
    }
}
