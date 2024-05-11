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
//! - [verifiy_shuffle]

mod decryption;
mod exponentiation;
mod plaintext_equality;
mod schnorr_proofs;

use thiserror::Error;

pub use decryption::verify_decryption;
pub use exponentiation::verify_exponentiation;
pub use plaintext_equality::verify_plaintext_equality;
pub use schnorr_proofs::verify_schnorr;

// enum representing the errors during the algorithms for zero knowledge proof
#[derive(Error, Debug)]
pub enum ZeroKnowledgeProofError {
    #[error(transparent)]
    SchnorrProofError(#[from] schnorr_proofs::SchnorrProofError),
    #[error(transparent)]
    ExponentiationError(#[from] exponentiation::ExponentiationError),
    #[error(transparent)]
    DecryptionProofError(#[from] decryption::DecryptionProofError),
}
