//! Headers response message types for the P2P protocol.
//!
//! This module contains the headers response message implementation, which is used
//! to send block header data from peers in response to `getheaders` requests.
//!
//! # Usage
//!
//! The `Headers` message is used to efficiently synchronize blockchain information
//! between peers. Instead of sending full blocks, only the headers are transmitted,
//! allowing for faster synchronization and reduced bandwidth usage.
//!
//! # Consensus Encoding
//!
//! The `Headers` struct manually implements `Encodable` and `Decodable` traits,
//! allowing it to be encoded and decoded according to Bitcoin's consensus rules.
//!
//! # Examples
//!
//! TODO: Add examples when the library is more mature.

use crate::blockdata::block::Header;
use crate::consensus::{Decodable, Encodable};

/// Represents a headers response message in the P2P protocol.
///
/// A `Headers` response contains an array of block headers, typically used to
/// synchronize blockchain information between peers.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Headers<H: Header> {
    /// A list of block headers returned in response to a `getheaders` request.
    pub headers: Vec<H>,
}

impl<H: Header> Headers<H> {
    /// Creates a new `Headers` response message with the specified headers.
    ///
    /// # Arguments
    ///
    /// * `headers` - A vector of block headers to include in the response.
    ///
    /// # Returns
    ///
    /// * `Headers` - A new instance of the Headers response message.
    pub fn new(headers: Vec<H>) -> Self {
        Self { headers }
    }

    /// Returns the list of headers in the response.
    ///
    /// # Returns
    ///
    /// * `&[Header]` - A slice of the headers in the response.
    pub fn headers(&self) -> &[H] {
        &self.headers
    }

    /// Returns the number of headers in the response.
    ///
    /// # Returns
    ///
    /// * `usize` - The number of headers in the response.
    pub fn len(&self) -> usize {
        self.headers.len()
    }

    /// Checks if the response contains no headers.
    ///
    /// # Returns
    ///
    /// * `bool` - True if the response contains no headers, false otherwise.
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "Won't fail on usize addition"
)]
impl<H: Header> Encodable for Headers<H> {
    fn consensus_encode<W: crate::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<usize, crate::io::Error> {
        let mut len = 0;
        // Encode the number of headers as a VarInt
        len +=
            crate::consensus::encode::VarInt::from(self.headers.len()).consensus_encode(writer)?;
        // Encode each header
        for header in &self.headers {
            len += header.consensus_encode(writer)?;
        }
        Ok(len)
    }
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "Cast is fine here as it can't fail"
)]
impl<H: Header> Decodable for Headers<H> {
    fn consensus_decode<R: crate::io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, crate::consensus::EncodeDecodeError> {
        // Decode the number of headers as a VarInt
        let len = crate::consensus::encode::VarInt::consensus_decode(reader)?.0;

        // Check that the length is within bounds
        if len > crate::consensus::MAX_VEC_SIZE as u64 {
            return Err(crate::consensus::EncodeDecodeError::ParseFailed(
                "Vector too large, exceeds MAX_VEC_SIZE",
            ));
        }

        // Create a vector to hold the headers
        let mut headers = Vec::with_capacity(len as usize);

        // Decode each header
        for _ in 0..len {
            headers.push(Decodable::consensus_decode(reader)?);
        }

        Ok(Headers { headers })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockdata::block::BitcoinHeader;
    use crate::hashes::Hash;
    use bitcoin::block::Header as InnerBitcoinHeader;
    use bitcoin::block::Version;
    use bitcoin::consensus::{Decodable, Encodable};
    use bitcoin::{BlockHash, CompactTarget, TxMerkleNode};

    fn create_test_header() -> BitcoinHeader {
        InnerBitcoinHeader {
            version: Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 0,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: 1,
        }
        .into()
    }

    #[test]
    fn test_headers_new() {
        let headers = vec![create_test_header(), create_test_header()];

        let response = Headers::new(headers.clone());

        assert_eq!(response.headers(), &headers);
    }

    #[test]
    fn test_headers_headers_access() {
        let headers = vec![create_test_header(), create_test_header()];

        let response = Headers::new(headers.clone());

        assert_eq!(response.headers(), &headers);
    }

    #[test]
    fn test_headers_round_trip() {
        let headers = vec![create_test_header(), create_test_header()];

        let original = Headers::new(headers);

        // Encode
        let mut encoded = Vec::new();
        original.consensus_encode(&mut encoded).unwrap();

        // Decode
        let mut cursor = std::io::Cursor::new(&encoded);
        let decoded = Headers::consensus_decode(&mut cursor).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_headers_len() {
        let headers = vec![create_test_header(), create_test_header()];

        let response = Headers::new(headers);

        assert_eq!(response.len(), 2);
    }

    #[test]
    fn test_headers_is_empty() {
        let response: Headers<BitcoinHeader> = Headers::new(vec![]);

        assert!(response.is_empty());
    }

    #[test]
    fn test_headers_is_not_empty() {
        let response = Headers::new(vec![create_test_header()]);

        assert!(!response.is_empty());
    }
}
