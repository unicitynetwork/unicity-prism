// See: https://developer.bitcoin.org/reference/p2p_networking.html#data-messages
// Only requests are implement as this client is not meant to relay.

mod get_blocks;
mod get_data;
mod inventory;

pub enum Message {
    GetBlocks(get_blocks::GetBlocks),
}
