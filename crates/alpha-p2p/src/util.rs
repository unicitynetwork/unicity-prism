#[cfg(test)]
pub(crate) mod test_util {
    use crate::hashes::Hash;

    pub fn hex_to_hash<const N: usize, H: Hash<Bytes = [u8; N]>>(
        hex_str: &str,
    ) -> Result<H, hex::FromHexError> {
        let bytes = hex::decode(hex_str)?;
        let mut array = [0u8; N];
        array.copy_from_slice(&bytes);
        Ok(H::from_byte_array(array))
    }
}
