pub use bitcoin::hashes::{Hash, hash_newtype, sha256d::Hash as Sha256Hash};

/// A SHA256D hash type specifically for Bitcoin message checksums
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChecksumHash(Sha256Hash);

impl ChecksumHash {
    /// Create a new checksum hash from the given data
    pub fn hash(data: &[u8]) -> Self {
        Self(Sha256Hash::hash(data))
    }

    /// Get the first 4 bytes of the hash as a checksum
    pub fn checksum(&self) -> [u8; 4] {
        let bytes = self.0.as_byte_array();
        [bytes[0], bytes[1], bytes[2], bytes[3]]
    }
}

impl From<Sha256Hash> for ChecksumHash {
    fn from(hash: Sha256Hash) -> Self {
        Self(hash)
    }
}

impl From<ChecksumHash> for Sha256Hash {
    fn from(checksum: ChecksumHash) -> Self {
        checksum.0
    }
}

impl AsRef<[u8]> for ChecksumHash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_byte_array()
    }
}
