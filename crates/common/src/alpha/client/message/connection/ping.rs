use rand::{RngCore, rng};
use unicity_prism_derive::ConsensusCodec;

/// Represents a Ping message in the P2P protocol.
///
/// A Ping message is used to check the liveness of a connection between peers.
/// It contains a nonce, which is a unique identifier for the ping message.
/// The nonce is used to match the corresponding Pong response.
///
/// # Arguments
///
/// * `nonce` - A unique identifier for the ping message.
///
/// # Example
///
/// ```ignore
/// use unicity_alphabridge::client::message::connection::ping::Ping;
///
/// let ping = Ping::new();
///
/// assert!(ping.nonce() != 0); // Nonce should be a random
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, ConsensusCodec)]
pub struct Ping {
    nonce: u64,
}

impl Ping {
    /// Creates a new Ping message with a random nonce.
    ///
    /// # Returns
    ///
    /// * `Ping` - A new instance of the Ping message with a random nonce.
    ///
    /// # Example
    ///
    /// TODO: Add example when the library is more mature.
    pub fn new() -> Ping {
        let nonce = rng().next_u64();
        Ping { nonce }
    }

    /// Creates a new Ping message with the given nonce.
    ///
    /// # Arguments
    ///
    /// * `nonce` - A unique identifier for the ping message.
    ///
    /// # Returns
    ///
    /// * `Ping` - A new instance of the Ping message.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use unicity_alphabridge::client::message::connection::ping::Ping;
    ///
    /// let ping = Ping::new(12345);
    ///
    /// assert_eq!(ping.nonce(), 12345);
    /// ```
    pub fn with_nonce(nonce: u64) -> Self {
        Self { nonce }
    }

    /// Creates a new Ping message with a random nonce using the provided RNG.
    ///
    /// # Arguments
    ///
    /// * `rng` - A mutable reference to a random number generator implementing
    ///   the `rand::Rng` trait.
    ///
    /// # Returns
    ///
    /// * `Ping` - A new instance of the Ping message with a random nonce.
    pub fn with_rng<R: rand::Rng + ?Sized>(rng: &mut R) -> Self {
        let nonce: u64 = rng.next_u64();
        Self { nonce }
    }

    /// Returns the nonce of the Ping message.
    ///
    /// # Returns
    ///
    /// * `u64` - The nonce of the Ping message.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use unicity_alphabridge::client::message::connection::ping::Ping;
    ///
    /// let ping = Ping::new(12345);
    ///
    /// assert_eq!(ping.nonce(), 12345);
    /// ```
    pub fn nonce(&self) -> u64 {
        self.nonce
    }
}

impl Default for Ping {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::consensus::{Decodable, Encodable};

    use super::Ping;

    #[test]
    fn test_ping_new() {
        let ping1 = Ping::new();
        let ping2 = Ping::new();
        assert_ne!(ping1.nonce(), ping2.nonce());
    }

    #[test]
    fn test_ping_with_nonce() {
        let nonce = 12345;
        let ping = Ping::with_nonce(nonce);
        assert_eq!(ping.nonce(), nonce);
    }

    #[test]
    fn test_ping_with_rng() {
        let mut rng = rand::rng();
        let ping1 = Ping::with_rng(&mut rng);
        let ping2 = Ping::with_rng(&mut rng);
        assert_ne!(ping1.nonce(), ping2.nonce());
    }

    #[test]
    fn test_encoded_ping() {
        let expected_hex = "0094102111e2af4d";
        let decoded_bytes = hex::decode(expected_hex).unwrap();
        let nonce = u64::from_le_bytes(decoded_bytes.try_into().unwrap());

        let ping = Ping::with_nonce(nonce);
        let mut encoded = Vec::new();
        ping.consensus_encode(&mut encoded).unwrap();
        assert_eq!(hex::encode(&encoded), expected_hex);
    }

    #[test]
    fn test_round_trip() {
        let original = Ping::new();
        let mut encoded = Vec::new();
        original.consensus_encode(&mut encoded).unwrap();

        let mut cursor = std::io::Cursor::new(&encoded);
        let decoded = Ping::consensus_decode(&mut cursor).unwrap();

        assert_eq!(original, decoded);
        assert_eq!(original.nonce(), decoded.nonce());
    }

    #[test]
    fn test_round_trip_with_known_nonce() {
        let nonce: u64 = 0x123456789ABCDEF0u64;
        let original = Ping::with_nonce(nonce);
        let mut encoded = Vec::new();
        original.consensus_encode(&mut encoded).unwrap();

        let mut cursor = std::io::Cursor::new(&encoded);
        let decoded = Ping::consensus_decode(&mut cursor).unwrap();

        assert_eq!(original, decoded);
        assert_eq!(original.nonce(), decoded.nonce());
    }

    #[test]
    fn test_empty_round_trip() {
        // Test with minimum possible encoding (nonce = 0)
        let original = Ping::with_nonce(0);
        let mut encoded = Vec::new();
        original.consensus_encode(&mut encoded).unwrap();

        assert_eq!(encoded.len(), 8); // u64 is 8 bytes

        let mut cursor = std::io::Cursor::new(&encoded);
        let decoded = Ping::consensus_decode(&mut cursor).unwrap();

        assert_eq!(original, decoded);
        assert_eq!(decoded.nonce(), 0);
    }
}
