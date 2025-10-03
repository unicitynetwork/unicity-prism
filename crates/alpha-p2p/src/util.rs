use bitcoin::{BlockHash, Txid};
use hex::FromHex;

use crate::hashes::Hash;

/// Convert a hex string to a Bitcoin hash type.
pub fn hex_to_hash<T>(hex: &str) -> Result<T, hex::FromHexError>
where
    T: From<[u8; 32]>,
{
    let bytes = <[u8; 32]>::from_hex(hex)?;
    Ok(T::from(bytes))
}

/// Convert a hex string to a Txid.
/// The hex string can be in either display format (little-endian) or internal
/// format (big-endian).
pub fn hex_to_txid(hex: &str) -> Result<Txid, hex::FromHexError> {
    let bytes = <[u8; 32]>::from_hex(hex)?;
    Ok(Txid::from_byte_array(bytes))
}

/// Convert a hex string to a BlockHash.
/// The hex string can be in either display format (little-endian) or internal
/// format (big-endian).
pub fn hex_to_blockhash(hex: &str) -> Result<BlockHash, hex::FromHexError> {
    let bytes = <[u8; 32]>::from_hex(hex)?;
    Ok(BlockHash::from_byte_array(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_to_txid() {
        let hex = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
        let txid = hex_to_txid(hex).unwrap();
        // Bitcoin hashes are displayed in reverse byte order
        assert_eq!(
            txid.to_string(),
            "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
        );
    }

    #[test]
    fn test_hex_to_blockhash() {
        let hex = "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048";
        let blockhash = hex_to_blockhash(hex).unwrap();
        // Bitcoin hashes are displayed in reverse byte order
        assert_eq!(
            blockhash.to_string(),
            "4860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000"
        );
    }

    #[test]
    fn test_invalid_hex() {
        let hex = "invalid_hex";
        assert!(hex_to_txid(hex).is_err());
        assert!(hex_to_blockhash(hex).is_err());
    }
}
