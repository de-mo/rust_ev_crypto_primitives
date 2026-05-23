// Copyright © 2023 Denis Morel
//
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

//! Crate implementing the cryptographic functions for E-Voting
//!
//! It is based on the specifications of Swiss Post, according to the following document version:
//! [Crypo-primitives](https://gitlab.com/swisspost-evoting/crypto-primitives/crypto-primitives), version 1.5.0
//!
//! The crate reduces actually at the necessary functions for the Verifier. The crate is grouped in modules releated
//! to themes, like the specifications
//!
//! The module `crate::basic_crypto_functions` contains a wrapper to openssl. Details about installation and functionalities
//! can be found on the crate [openssl].
//!
//! The crate ist based on [rug] that is strongly performant, but GMP must be installed for compilation.
//! See the requirements and installation path in the crate documentation [rug](https://crates.io/crates/rug)
//!
//! If a method should return an error, then each error type is specified per module and is transparent
//! to the user of the crate.
//!
//! # Features
//!
//! Following features are possible:
//! - "checks": The feature will perform checks of the input data, according to the specifications of Swiss Post.
//!   This reduces the performance. If the checks are performed during the usage of the crate, it is recommended,
//!   not to activate the feature
//! - "gmpmee": Use the library gmpmee for fixed exponentiation. See [rug-gmpmee](https://docs.rs/rug-gmpmee/0.1.4/rug_gmpmee/) for details
//!

pub mod alphabets;
pub mod argon2;
pub mod basic_crypto_functions;
mod byte_array;
pub mod direct_trust;
mod domain;
pub mod elgamal;
mod hashing;
mod integer;
pub mod mix_net;
mod number_theory;
pub mod random;
mod shared_error;
pub mod signature;
pub mod string;
pub mod symmetric_authenticated_encryption;
pub mod zero_knowledge_proofs;

pub use byte_array::{ByteArray, ByteArrayError, DecodeTrait, EncodeTrait};
pub use domain::*;
pub use hashing::{HashError, HashableMessage, RecursiveHashTrait, hash_and_square};
pub use integer::{
    ConstantsTrait, ConvertStringTait, Hexa, IntegerOperationError, ModExponentiateError,
    OperationsTrait, StringToIntegerError, ToByteArryTrait, prepare_fixed_based_optimization,
};
pub use number_theory::{
    IsPrimeTrait, JacobiError, JacobiTrait, NotPrimeError, QuadraticResidueTrait, SmallPrimeError,
    SmallPrimeTrait,
};
pub use rug::{Integer, integer::ParseIntegerError, ops};
pub use shared_error::{NotOddError, NotPositiveError};

/// The length of the group parameter `p` according to the security level in the specifications
pub const GROUP_PARAMETER_P_LENGTH: usize = 3072;

/// The length of the group parameter `q` according to the security level in the specifications
pub const GROUP_PARAMETER_Q_LENGTH: usize = 3071;

/// The security length according to the security level in the specifications
pub const SECURITY_STRENGTH: usize = 128;

#[cfg(test)]
mod test_json_data {
    use crate::{
        ByteArray, DecodeTrait, Integer,
        elgamal::{Ciphertext, EncryptionParameters},
    };
    use serde_json::Value;
    use std::path::Path;

    const TEST_DATA_DIR: &str = "test_data";

    pub fn get_test_cases_from_json_file(subdir_name: &str, filename: &str) -> Vec<Value> {
        let test_file = Path::new("./")
            .join(TEST_DATA_DIR)
            .join(subdir_name)
            .join(filename);
        let json = std::fs::read_to_string(test_file).unwrap();
        serde_json::from_str(&json).unwrap()
    }

    pub fn json_array_value_to_array_string(array: &Value) -> Vec<String> {
        array
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect()
    }

    pub fn json_array_64_value_to_array_integer(array: &Value) -> Vec<Integer> {
        Integer::base_64_decode_vector(
            &json_array_value_to_array_string(array)
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>(),
        )
        .unwrap()
    }

    pub fn json_64_value_to_integer(value: &Value) -> Integer {
        Integer::base64_decode(value.as_str().unwrap()).unwrap()
    }

    pub fn json_64_value_to_byte_array(value: &Value) -> ByteArray {
        ByteArray::base64_decode(value.as_str().unwrap()).unwrap()
    }

    pub struct EncryptionParametersValues(pub Integer, pub Integer, pub Integer);

    impl From<&EncryptionParametersValues> for EncryptionParameters {
        fn from(value: &EncryptionParametersValues) -> Self {
            EncryptionParameters::from((&value.0, &value.1, &value.2))
        }
    }

    pub fn json_value_to_encryption_parameters(values: &Value) -> EncryptionParameters {
        EncryptionParameters::from(&json_value_to_encryption_parameters_values(values))
    }

    pub fn json_value_to_encryption_parameters_values(
        values: &Value,
    ) -> EncryptionParametersValues {
        EncryptionParametersValues(
            json_64_value_to_integer(&values["p"]),
            json_64_value_to_integer(&values["q"]),
            json_64_value_to_integer(&values["g"]),
        )
    }

    pub struct CiphertextValues {
        pub gamma: Integer,
        pub phis: Vec<Integer>,
    }

    impl From<&CiphertextValues> for Ciphertext {
        fn from(value: &CiphertextValues) -> Self {
            Ciphertext {
                gamma: value.gamma.clone(),
                phis: value.phis.clone(),
            }
        }
    }

    pub fn json_values_to_ciphertext_values(values: &Value) -> CiphertextValues {
        CiphertextValues {
            gamma: json_64_value_to_integer(&values["gamma"]),
            phis: json_array_64_value_to_array_integer(&values["phis"]),
        }
    }

    pub fn json_values_to_ciphertext(values: &Value) -> Ciphertext {
        Ciphertext::from(&json_values_to_ciphertext_values(values))
    }
}
