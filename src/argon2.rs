// Copyright © 2024 Denis Morel

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

//! Module that implement key derivation functions with argon2id
//!
use crate::basic_crypto_functions::{argon2_has_password, random_bytes, BasisCryptoError};
use crate::ByteArray;

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

/// Object containing the parameters and the methods creating the key derivation functions
/// with argon2id
///
/// # Usage (example)
/// ```
/// use rust_ev_crypto_primitives::{Argon2id, ByteArray, Decode};
/// let key = ByteArray::base64_decode("dGVzdCBwYXNzd29yZA==").unwrap();
/// let salt = ByteArray::base64_decode("1YBBD3ZMrqhZr5bLsddvSA==").unwrap();
/// let expected_tag = ByteArray::base64_decode("qYOoULGijoHNdsDaz6PqnVrTriSLuTB74cGtqHEbO7o=").unwrap();
/// let tag = Argon2id::new_test().get_argon2id(&key, &salt).unwrap();
/// assert_eq!(tag, expected_tag);
/// ```
pub struct Argon2id {
    memory_usage_parameter: u32,
    parallelism_parameter: u32,
    iteration_count: u32,
    output_size: usize,
}

impl Argon2id {
    /// New object with standard parameters (see specifications of Swiss Post)
    pub fn new_standard() -> Self {
        Self {
            memory_usage_parameter: 2u32.pow(STANDARD_MEMORY_EXPONENT),
            parallelism_parameter: STANDARD_PARALLELISM,
            iteration_count: STANDARD_ITERATIONS,
            output_size: OUTPUT_SIZE,
        }
    }

    /// New object with less parameters (see specifications of Swiss Post)
    pub fn new_less() -> Self {
        Self {
            memory_usage_parameter: 2u32.pow(LESS_MEMORY_EXPONENT),
            parallelism_parameter: LESS_PARALLELISM,
            iteration_count: LESS_ITERATIONS,
            output_size: OUTPUT_SIZE,
        }
    }

    /// New object with test parameters (see specifications of Swiss Post)
    pub fn new_test() -> Self {
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
    ) -> Result<(ByteArray, ByteArray), BasisCryptoError> {
        let s = random_bytes(16)?;
        Ok((self.get_argon2id(input_keying_material, &s)?, s))
    }

    /// GetArgon2id according the specifications of Swiss Post
    pub fn get_argon2id(
        &self,
        input_keying_material: &ByteArray,
        salt: &ByteArray,
    ) -> Result<ByteArray, BasisCryptoError> {
        argon2_has_password(
            self.memory_usage_parameter,
            self.parallelism_parameter,
            self.iteration_count,
            self.output_size,
            input_keying_material,
            salt,
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Decode;

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
