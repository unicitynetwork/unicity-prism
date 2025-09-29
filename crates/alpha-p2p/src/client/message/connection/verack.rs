use alpha_p2p_derive::ConsensusCodec;

/// A VerAck message used in peer-to-peer communication to acknowledge a version message.
///
/// The VerAck (version acknowledgment) message is sent after receiving a version
/// message to confirm the connection handshake. It contains a nonce that should
/// match the nonce from the corresponding version message, allowing peers to verify
/// that they are properly connected and synchronized.
///
/// # Arguments
///
/// * `nonce` - A unique identifier for the verack message, typically matching
///   the nonce from a Version message.
///
/// # Example
///
/// ```ignore
/// use alpha_p2p::client::message::connection::verack::VerAck;
///
/// let verack = VerAck::new(12345);
///
/// assert_eq!(verack.nonce(), 12345);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, ConsensusCodec)]
pub struct VerAck {
    nonce: u64,
}

impl VerAck {
    /// Creates a new VerAck message with the given nonce.
    ///
    /// # Arguments
    ///
    /// * `nonce` - A unique identifier for the verack message, typically matching
    ///   the nonce from a Version message.
    ///
    /// # Returns
    ///
    /// * `VerAck` - A new instance of the VerAck message.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use alpha_p2p::client::message::connection::verack::VerAck;
    ///
    /// let verack = VerAck::new(12345);
    ///
    /// assert_eq!(verack.nonce(), 12345);
    /// ```
    pub fn new(nonce: u64) -> VerAck {
        VerAck { nonce }
    }

    /// Returns the nonce of the VerAck message.
    ///
    /// # Returns
    ///
    /// * `u64` - The nonce of the VerAck message.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use alpha_p2p::client::message::connection::verack::VerAck;
    ///
    /// let verack = VerAck::new(12345);
    ///
    /// assert_eq!(verack.nonce(), 12345);
    /// ```
    pub fn nonce(&self) -> u64 {
        self.nonce
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::{Decodable, Encodable};
    use hex;
    use rand::{rng, RngCore};
    use std::io::Cursor;

    #[test]
    fn test_verack_new() {
        let verack1 = VerAck::new(rng().next_u64());
        let verack2 = VerAck::new(rng().next_u64());
        assert_ne!(verack1.nonce(), verack2.nonce());
    }

    #[test]
    fn test_verack_with_nonce() {
        let nonce = 12345;
        let verack = VerAck::new(nonce);
        assert_eq!(verack.nonce(), nonce);
    }

    #[test]
    fn test_verack_with_rng() {
        let mut rng = rand::rng();
        let verack1 = VerAck::new(rng.next_u64());
        let verack2 = VerAck::new(rng.next_u64());
        assert_ne!(verack1.nonce(), verack2.nonce());
    }

    #[test]
    fn test_encoded_verack() {
        let expected_hex = "0094102111e2af4d";
        let decoded_bytes = hex::decode(expected_hex).unwrap();
        let nonce = u64::from_le_bytes(decoded_bytes.try_into().unwrap());

        let verack = VerAck::new(nonce);
        let mut encoded = Vec::new();
        verack.consensus_encode(&mut encoded).unwrap();
        assert_eq!(hex::encode(&encoded), expected_hex);
    }

    #[test]
    fn test_round_trip() {
        let original = VerAck::new(rng().next_u64());
        let mut encoded = Vec::new();
        original.consensus_encode(&mut encoded).unwrap();

        let mut cursor = Cursor::new(&encoded);
        let decoded = VerAck::consensus_decode(&mut cursor).unwrap();

        assert_eq!(original, decoded);
        assert_eq!(original.nonce(), decoded.nonce());
    }

    #[test]
    fn test_round_trip_with_known_nonce() {
        let nonce: u64 = 0x123456789ABCDEF0u64;
        let original = VerAck::new(nonce);
        let mut encoded = Vec::new();
        original.consensus_encode(&mut encoded).unwrap();

        let mut cursor = Cursor::new(&encoded);
        let decoded = VerAck::consensus_decode(&mut cursor).unwrap();

        assert_eq!(original, decoded);
        assert_eq!(original.nonce(), decoded.nonce());
    }

    #[test]
    fn test_empty_round_trip() {
        let original = VerAck::new(0);
        let mut encoded = Vec::new();
        original.consensus_encode(&mut encoded).unwrap();

        assert_eq!(encoded.len(), 8);

        let mut cursor = Cursor::new(&encoded);
        let decoded = VerAck::consensus_decode(&mut cursor).unwrap();

        assert_eq!(original, decoded);
        assert_eq!(decoded.nonce(), 0);
    }
}
