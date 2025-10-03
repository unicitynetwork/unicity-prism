use unicity_prism_derive::ConsensusCodec;

/// A Pong message used in peer-to-peer communication to respond to a Ping
/// message. The Pong message contains a nonce that matches the nonce from the
/// corresponding Ping message, allowing the sender to verify that the Pong is a
/// response to their Ping.
///
/// This message is part of the connection management in the Alpha protocol,
/// helping to maintain active connections between peers.
///
/// # Arguments
///
/// * `nonce` - A unique identifier for the pong message, typically matching the
///   nonce from a Ping message.
///
/// # Example
///
/// ```ignore
/// use unicity_alphabridge::client::message::connection::pong::Pong;
///
/// let pong = Pong::new(12345);
///
/// assert_eq!(pong.nonce(), 12345);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, ConsensusCodec)]
pub struct Pong {
    nonce: u64,
}

impl Pong {
    /// Creates a new Pong message with the given nonce.
    ///
    /// # Arguments
    ///
    /// * `nonce` - A unique identifier for the pong message, typically matching
    ///   the nonce from a Ping message.
    ///
    /// # Returns
    ///
    /// * `Pong` - A new instance of the Pong message.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use unicity_alphabridge::client::message::connection::pong::Pong;
    ///
    /// let pong = Pong::new(12345);
    ///
    /// assert_eq!(pong.nonce(), 12345);
    /// ```
    pub fn new(nonce: u64) -> Pong {
        Pong { nonce }
    }

    /// Returns the nonce of the Pong message.
    ///
    /// # Returns
    ///
    /// * `u64` - The nonce of the Pong message.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use unicity_alphabridge::client::message::connection::pong::Pong;
    ///
    /// let pong = Pong::new(12345);
    ///
    /// assert_eq!(pong.nonce(), 12345);
    /// ```
    pub fn nonce(&self) -> u64 {
        self.nonce
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use bitcoin::consensus::{Decodable, Encodable};
    use hex;
    use rand::{RngCore, rng};

    use super::*;

    #[test]
    fn test_pong_new() {
        let pong1 = Pong::new(rng().next_u64());
        let pong2 = Pong::new(rng().next_u64());
        assert_ne!(pong1.nonce(), pong2.nonce());
    }

    #[test]
    fn test_pong_with_nonce() {
        let nonce = 12345;
        let pong = Pong::new(nonce);
        assert_eq!(pong.nonce(), nonce);
    }

    #[test]
    fn test_pong_with_rng() {
        let mut rng = rand::rng();
        let pong1 = Pong::new(rng.next_u64());
        let pong2 = Pong::new(rng.next_u64());
        assert_ne!(pong1.nonce(), pong2.nonce());
    }

    #[test]
    fn test_encoded_pong() {
        let expected_hex = "0094102111e2af4d";
        let decoded_bytes = hex::decode(expected_hex).unwrap();
        let nonce = u64::from_le_bytes(decoded_bytes.try_into().unwrap());

        let pong = Pong::new(nonce);
        let mut encoded = Vec::new();
        pong.consensus_encode(&mut encoded).unwrap();
        assert_eq!(hex::encode(&encoded), expected_hex);
    }

    #[test]
    fn test_round_trip() {
        let original = Pong::new(rng().next_u64());
        let mut encoded = Vec::new();
        original.consensus_encode(&mut encoded).unwrap();

        let mut cursor = Cursor::new(&encoded);
        let decoded = Pong::consensus_decode(&mut cursor).unwrap();

        assert_eq!(original, decoded);
        assert_eq!(original.nonce(), decoded.nonce());
    }

    #[test]
    fn test_round_trip_with_known_nonce() {
        let nonce: u64 = 0x123456789ABCDEF0u64;
        let original = Pong::new(nonce);
        let mut encoded = Vec::new();
        original.consensus_encode(&mut encoded).unwrap();

        let mut cursor = Cursor::new(&encoded);
        let decoded = Pong::consensus_decode(&mut cursor).unwrap();

        assert_eq!(original, decoded);
        assert_eq!(original.nonce(), decoded.nonce());
    }

    #[test]
    fn test_empty_round_trip() {
        let original = Pong::new(0);
        let mut encoded = Vec::new();
        original.consensus_encode(&mut encoded).unwrap();

        assert_eq!(encoded.len(), 8);

        let mut cursor = Cursor::new(&encoded);
        let decoded = Pong::consensus_decode(&mut cursor).unwrap();

        assert_eq!(original, decoded);
        assert_eq!(decoded.nonce(), 0);
    }
}
