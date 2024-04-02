use crate::{BasisCryptoError, ByteArray};
use openssl::rand::rand_bytes;

pub fn random_bytes(size: usize) -> Result<ByteArray, BasisCryptoError> {
    let mut buf = vec![0u8; size];
    rand_bytes(&mut buf).map_err(|e| BasisCryptoError::RandomError {
        msg: "Call rand_bytes in random_bytes".to_string(),
        source: e,
    })?;
    Ok(ByteArray::from_bytes(&buf))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_size() {
        assert_eq!(random_bytes(32).unwrap().len(), 32);
        assert_eq!(random_bytes(16).unwrap().len(), 16);
    }
}
