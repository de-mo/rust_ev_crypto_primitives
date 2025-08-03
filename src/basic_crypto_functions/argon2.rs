// Copyright © 2023 Denis Morel

// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU General Public License and
// a copy of the GNU General Public License along with this program. If not, see
// <https://www.gnu.org/licenses/>.

use super::{BasisCryptoError, BasisCryptoErrorRepr};
use crate::ByteArray;
pub(super) use argon2::Error as Argon2ErrorExt;
use argon2::{Algorithm, Argon2, ParamsBuilder, Version};
use thiserror::Error;

#[derive(Error, Debug)]
pub(super) enum Argon2Error {
    #[error("Error building the parameters to hash the password")]
    BuildParam { source: Argon2ErrorExt },
    #[error("Error hashing the password")]
    HassPassword { source: Argon2ErrorExt },
}

/// Hash password with Argon2id
pub fn argon2_hash_password(
    memory: u32,
    parallelism: u32,
    iterations: u32,
    output_size: usize,
    pwd: &ByteArray,
    salt: &ByteArray,
) -> Result<ByteArray, BasisCryptoError> {
    argon2_hash_password_repr(memory, parallelism, iterations, output_size, pwd, salt)
        .map_err(BasisCryptoErrorRepr::from)
        .map_err(BasisCryptoError::from)
}

fn argon2_hash_password_repr(
    memory: u32,
    parallelism: u32,
    iterations: u32,
    output_size: usize,
    pwd: &ByteArray,
    salt: &ByteArray,
) -> Result<ByteArray, Argon2Error> {
    let params = ParamsBuilder::new()
        .m_cost(memory)
        .p_cost(parallelism)
        .t_cost(iterations)
        .output_len(output_size)
        .build()
        .map_err(|e| Argon2Error::BuildParam { source: e })?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = vec![0u8; output_size];
    argon
        .hash_password_into(pwd.to_bytes(), salt.to_bytes(), &mut out)
        .map_err(|e| Argon2Error::HassPassword { source: e })?;
    Ok(ByteArray::from_bytes(&out))
}
