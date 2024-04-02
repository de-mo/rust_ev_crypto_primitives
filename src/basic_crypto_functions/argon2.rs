// Copyright © 2023 Denis Morel

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU Lesser General Public License and
// a copy of the GNU General Public License along with this program. If not, see
// <https://www.gnu.org/licenses/>.

use super::BasisCryptoError;
use crate::ByteArray;
use argon2::{Algorithm, Argon2, ParamsBuilder, Version};

pub(super) use argon2::Error as Argon2Error;

/// Hash password with Argon2id
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
