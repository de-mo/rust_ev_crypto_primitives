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

//! Implementation of the necessary algorithms used for the zero-knowledge proofs of Swiss Post:
//! - [verify_schnorr]
//! - [verify_exponentiation]
//! - [verify_decryption]
//! - [verify_plaintext_equality]

mod decryption;
mod exponentiation;
mod plaintext_equality;
mod schnorr_proofs;

pub use decryption::{verify_decryption, DecryptionProofError};
pub use exponentiation::{verify_exponentiation, ExponentiationProofError};
pub use plaintext_equality::{verify_plaintext_equality, PlaintextProofError};
pub use schnorr_proofs::verify_schnorr;

#[cfg(test)]
mod test {
    use serde_json::Value;

    use crate::{
        test_json_data::{json_64_value_to_integer, json_array_64_value_to_array_integer},
        Integer,
    };

    pub struct Proof {
        pub e: Integer,
        pub z: Integer,
    }

    pub struct ProofVec {
        pub e: Integer,
        pub z: Vec<Integer>,
    }

    pub fn proof_from_json_values(values: &Value) -> Proof {
        Proof {
            e: json_64_value_to_integer(&values["e"]),
            z: json_64_value_to_integer(&values["z"]),
        }
    }

    pub fn proof_vec_from_json_values(values: &Value) -> ProofVec {
        ProofVec {
            e: json_64_value_to_integer(&values["e"]),
            z: json_array_64_value_to_array_integer(&values["z"]),
        }
    }
}
