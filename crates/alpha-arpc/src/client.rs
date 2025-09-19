use jsonrpsee::core::__reexports::serde_json;
use jsonrpsee::core::client::ClientT;
use jsonrpsee::core::traits::ToRpcParams;
use jsonrpsee::http_client::HttpClient as Client;
use thiserror::Error;
use serde_json::value::RawValue;

type AlphaRpcResult<T> = Result<T, AlphaRpcError>;

#[derive(serde::Serialize)]
struct BlockParams {
    hash: String,
    verbosity: Option<u8>,
}

#[derive(Debug, Error)]
pub enum AlphaRpcError {
    #[error("Client error: {0}")]
    ClientError(jsonrpsee::core::ClientError),
    #[error("Invalid response")]
    InvalidResponse,
}

pub struct AlphaRpcClient {
    client: Client,
}

impl ToRpcParams for BlockParams {
    fn to_rpc_params(self) -> Result<Option<Box<RawValue>>, serde_json::Error> {
        let json = serde_json::value::to_raw_value(&self)?;
        Ok(Some(json))
    }
}

impl AlphaRpcClient {
    pub fn new(url: String) -> AlphaRpcResult<Self> {
        let client = Client::builder().build(url)?;
        Ok(Self { client })
    }

    pub fn best_block_hash(&self) -> AlphaRpcResult<u64> {
        let count: u64 = self.client.request("getbestblockhash", None).map_err(AlphaRpcError::ClientError)?;
        Ok(count)
    }
}
