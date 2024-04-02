use super::BasisCryptoError;
use crate::ByteArray;
use argon2::{Algorithm, Argon2, ParamsBuilder, Version};

pub(super) use argon2::Error as Argon2Error;

pub fn argon2_has_password(
    memory: u32,
    parallelism: u32,
    iterations: u32,
    output_size: usize,
    pwd: &ByteArray,
    salt: &ByteArray,
) -> Result<ByteArray, BasisCryptoError> {
    let params = ParamsBuilder::new()
        .m_cost(memory)
        .p_cost(parallelism)
        .t_cost(iterations)
        .output_len(output_size)
        .build()
        .map_err(|e| BasisCryptoError::Argon2Error {
            msg: "Creating the parameters".to_string(),
            argon2_error_source: e,
        })?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = vec![0u8; output_size];
    argon
        .hash_password_into(&pwd.to_bytes(), &salt.to_bytes(), &mut out)
        .map_err(|e| BasisCryptoError::Argon2Error {
            msg: "Creating the parameters".to_string(),
            argon2_error_source: e,
        })?;
    Ok(ByteArray::from_bytes(&out))
}
