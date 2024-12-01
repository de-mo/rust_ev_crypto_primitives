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

//! Implementation of El Gamal functionalitiies

mod ciphertext;
mod combined_public_keys;
mod dercryption;
mod encryption_parameters;

pub use ciphertext::Ciphertext;
pub use combined_public_keys::combine_public_keys;
pub use dercryption::{verify_decryptions, VerifyDecryptionsResult};
pub use encryption_parameters::{EncryptionParameterDomainError, EncryptionParameters};

use crate::{
    basic_crypto_functions::BasisCryptoError, zero_knowledge_proofs::ZeroKnowledgeProofError,
    Integer, NumberTheoryError,
};
use thiserror::Error;

// Enum reprsenting the elgamal errors
#[derive(Error, Debug)]
pub enum ElgamalError {
    #[error(transparent)]
    OpenSSLError(#[from] BasisCryptoError),
    #[error("To few number of small primes found. Expcted: {expected}, found: {found}")]
    TooFewSmallPrimeNumbers { expected: usize, found: usize },
    #[error("Number {0} with value {1} is not prime")]
    NotPrime(String, Integer),
    #[error("The relation p=2q+1 is not satisfied")]
    CheckRelationPQ,
    #[error("The value should not be one")]
    CheckNotOne,
    #[error(transparent)]
    CheckNumberTheory(#[from] NumberTheoryError),
    #[error("l must be between 1 and k")]
    LNotCorrect,
    #[error("The length of the ciphertext vectors must be the same")]
    CipherTextVectorsLenNotSame,
    #[error("The length of the decryption proofs must be the same than the ciphertext vectors")]
    DecryptionProofLenNotSame,
    #[error("No cihpertexts")]
    NoCiphertext,
    #[error("l not consistent over the ciphertext")]
    LNotConsistentOverCiphertexts,
    #[error("l not consistent over the proofs")]
    LNotConsistentForTheProofs,
    #[error(transparent)]
    ZeroKnowledgeProofError(#[from] ZeroKnowledgeProofError),
}
