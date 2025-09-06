// Copyright © 2024 Denis Morel

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

//! Module that implement key derivation functions with argon2id
//!

use crate::{
    basic_crypto_functions::{argon2_hash_password, random_bytes, BasisCryptoError},
    ByteArray,
};
use thiserror::Error;

/// The size of the salt
pub const ARGON2_SALT_SIZE: usize = 16;

const STANDARD_MEMORY_EXPONENT: u32 = 21;
const STANDARD_PARALLELISM: u32 = 4;
const STANDARD_ITERATIONS: u32 = 1;
const LESS_MEMORY_EXPONENT: u32 = 16;
const LESS_PARALLELISM: u32 = 4;
const LESS_ITERATIONS: u32 = 3;
const TEST_MEMORY_EXPONENT: u32 = 14;
const TEST_PARALLELISM: u32 = 4;
const TEST_ITERATIONS: u32 = 1;
const OUTPUT_SIZE: usize = 32;

#[derive(Error, Debug)]
#[error(transparent)]
pub struct Argon2Error(#[from] Argon2ErrorRepr);

#[derive(Error, Debug)]
pub enum Argon2ErrorRepr {
    #[error("Error in gen_argon2id generating the salt")]
    Salt { source: BasisCryptoError },
    #[error("Error in gen_argon2id getting argon2i")]
    GetArgon2i { source: Box<Argon2Error> },
    #[error("Error in get_argon2id hashing the password")]
    HashPwd { source: BasisCryptoError },
}

#[derive(Copy, Clone, Eq, PartialEq, Default)]
pub enum Argon2idParameters {
    #[default]
    Standard,
    Less,
    Test,
}

/// Object containing the parameters and the methods creating the key derivation functions
/// with argon2id
///
/// # Usage (example)
/// ```
/// use rust_ev_crypto_primitives::{argon2::{Argon2id, Argon2idParameters}, ByteArray, DecodeTrait};
/// let key = ByteArray::base64_decode("dGVzdCBwYXNzd29yZA==").unwrap();
/// let salt = ByteArray::base64_decode("1YBBD3ZMrqhZr5bLsddvSA==").unwrap();
/// let expected_tag = ByteArray::base64_decode("qYOoULGijoHNdsDaz6PqnVrTriSLuTB74cGtqHEbO7o=").unwrap();
/// let tag = Argon2id::new(Argon2idParameters::Test).get_argon2id(&key, &salt).unwrap();
/// assert_eq!(tag, expected_tag);
/// ```
pub struct Argon2id {
    memory_usage_parameter: u32,
    parallelism_parameter: u32,
    iteration_count: u32,
    output_size: usize,
}

impl Argon2id {
    pub fn new(parameters: Argon2idParameters) -> Self {
        match parameters {
            Argon2idParameters::Standard => Self::new_standard(),
            Argon2idParameters::Less => Self::new_less(),
            Argon2idParameters::Test => Self::new_test(),
        }
    }

    /// New object with standard parameters (see specifications of Swiss Post)
    fn new_standard() -> Self {
        Self {
            memory_usage_parameter: 2u32.pow(STANDARD_MEMORY_EXPONENT),
            parallelism_parameter: STANDARD_PARALLELISM,
            iteration_count: STANDARD_ITERATIONS,
            output_size: OUTPUT_SIZE,
        }
    }

    /// New object with less parameters (see specifications of Swiss Post)
    fn new_less() -> Self {
        Self {
            memory_usage_parameter: 2u32.pow(LESS_MEMORY_EXPONENT),
            parallelism_parameter: LESS_PARALLELISM,
            iteration_count: LESS_ITERATIONS,
            output_size: OUTPUT_SIZE,
        }
    }

    /// New object with test parameters (see specifications of Swiss Post)
    fn new_test() -> Self {
        Self {
            memory_usage_parameter: 2u32.pow(TEST_MEMORY_EXPONENT),
            parallelism_parameter: TEST_PARALLELISM,
            iteration_count: TEST_ITERATIONS,
            output_size: OUTPUT_SIZE,
        }
    }

    /// GenArgon2id according the specifications of Swiss Post
    pub fn gen_argon2id(
        &self,
        input_keying_material: &ByteArray,
    ) -> Result<(ByteArray, ByteArray), Argon2Error> {
        let salt = random_bytes(16)
            .map_err(|e| Argon2ErrorRepr::Salt { source: e })
            .map_err(Argon2Error::from)?;
        Ok((
            self.get_argon2id(input_keying_material, &salt)
                .map_err(|e| Argon2ErrorRepr::GetArgon2i {
                    source: Box::new(e),
                })
                .map_err(Argon2Error::from)?,
            salt,
        ))
    }

    /// GetArgon2id according the specifications of Swiss Post
    pub fn get_argon2id(
        &self,
        input_keying_material: &ByteArray,
        salt: &ByteArray,
    ) -> Result<ByteArray, Argon2Error> {
        argon2_hash_password(
            self.memory_usage_parameter,
            self.parallelism_parameter,
            self.iteration_count,
            self.output_size,
            input_keying_material,
            salt,
        )
        .map_err(|e| Argon2ErrorRepr::HashPwd { source: e })
        .map_err(Argon2Error::from)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::DecodeTrait;

    #[test]
    fn verify_argon2id_0() {
        let k = ByteArray::base64_decode("dGVzdCBwYXNzd29yZA==").unwrap();
        let s = ByteArray::base64_decode("1YBBD3ZMrqhZr5bLsddvSA==").unwrap();
        let t = ByteArray::base64_decode("qYOoULGijoHNdsDaz6PqnVrTriSLuTB74cGtqHEbO7o=").unwrap();
        let res = Argon2id::new_test().get_argon2id(&k, &s);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), t)
    }

    #[test]
    fn verify_argon2id_1() {
        let k = ByteArray::base64_decode("AQIDBAUGBwgJCgsMDQ4P").unwrap();
        let s = ByteArray::base64_decode("O8S5yOiqoVogtM1uFZrZiA==").unwrap();
        let t = ByteArray::base64_decode("OmiogN6kLFBrEeMiaMEtST5UKF3gIODDzk9gEsK2c8k=").unwrap();
        let res = Argon2id::new_test().get_argon2id(&k, &s);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), t)
    }

    #[test]
    fn verify_argon2id_2() {
        let k = ByteArray::base64_decode("QFJlYUxMeVN0cjBuNlBhJCRXMHJkLW9yLWlzLWl0Pw==").unwrap();
        let s = ByteArray::base64_decode("XaSBXQKboGg7T5UTGym6RA==").unwrap();
        let t = ByteArray::base64_decode("piRMhPWx39FRDCU9DsWLLVSak5560rproX5JGDap/UQ=").unwrap();
        let res = Argon2id::new_test().get_argon2id(&k, &s);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), t)
    }

    #[test]
    fn verify_gen_argon2id() {
        let k = ByteArray::base64_decode("QFJlYUxMeVN0cjBuNlBhJCRXMHJkLW9yLWlzLWl0Pw==").unwrap();
        let res = Argon2id::new_test().gen_argon2id(&k);
        assert!(res.is_ok());
        let (t, s) = res.unwrap();
        assert_eq!(Argon2id::new_test().get_argon2id(&k, &s).unwrap(), t)
    }
}
