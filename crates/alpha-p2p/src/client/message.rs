// See: https://developer.bitcoin.org/reference/p2p_networking.html#data-messages
// Only requests are implement as this client is not meant to relay.

pub mod get_data;
pub mod get_headers;
pub mod inventory;

use get_headers::GetHeaders;

pub enum Message {
    Connection(Connection),
    Request(Request),
    Response(Response),
}

pub enum Connection {
    Version,
    VerAck,
    Ping,
    Pong,
    SendHeaders,
}

pub enum Request {
    GetHeaders(GetHeaders),
}

pub enum Response {
    Headers,
    Block,
    Tx,
    NotFound,
}
