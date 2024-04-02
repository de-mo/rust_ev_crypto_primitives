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

pub struct Argon2id {
    memory_usage_parameter: u32,
    parallelism_parameter: u32,
    iteration_count: u32,
    output_size: usize,
}

impl Argon2id {
    pub fn new_standard() -> Self {
        Self {
            memory_usage_parameter: 2u32.pow(STANDARD_MEMORY_EXPONENT),
            parallelism_parameter: STANDARD_PARALLELISM,
            iteration_count: STANDARD_ITERATIONS,
            output_size: OUTPUT_SIZE,
        }
    }

    pub fn new_less() -> Self {
        Self {
            memory_usage_parameter: 2u32.pow(LESS_MEMORY_EXPONENT),
            parallelism_parameter: LESS_PARALLELISM,
            iteration_count: LESS_ITERATIONS,
            output_size: OUTPUT_SIZE,
        }
    }

    pub fn new_test() -> Self {
        Self {
            memory_usage_parameter: 2u32.pow(TEST_MEMORY_EXPONENT),
            parallelism_parameter: TEST_PARALLELISM,
            iteration_count: TEST_ITERATIONS,
            output_size: OUTPUT_SIZE,
        }
    }

    pub fn gen_argon2id(
        &self,
        input_keying_material: &ByteArray,
    ) -> Result<(ByteArray, ByteArray), BasisCryptoError> {
        let s = random_bytes(16)?;
        Ok((self.get_argon2id(input_keying_material, &s)?, s))
    }

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
