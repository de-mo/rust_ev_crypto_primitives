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

//! Implementation of El Gamal functionalitiies

mod ciphertext;
mod combined_public_keys;
mod dercryption;
mod encryption_parameters;

pub use ciphertext::Ciphertext;
use ciphertext::CiphertextError;
pub use combined_public_keys::combine_public_keys;
use combined_public_keys::CombinePublicKeysError;
use dercryption::DecryptionError;
pub use dercryption::{verify_decryptions, VerifyDecryptionsResult};
use encryption_parameters::EncryptionParameterError;
pub use encryption_parameters::{EncryptionParameterDomainError, EncryptionParameters};
use thiserror::Error;

#[derive(Error, Debug)]
#[error(transparent)]
/// Errors in Elgamal operations
pub struct ElgamalError(#[from] ElgamalErrorRepr);

// Enum reprsenting the elgamal errors
#[derive(Error, Debug)]
enum ElgamalErrorRepr {
    #[error(transparent)]
    EncryptionParameter(#[from] EncryptionParameterError),
    #[error(transparent)]
    Ciphertext(#[from] CiphertextError),
    #[error(transparent)]
    Decryption(#[from] DecryptionError),
    #[error(transparent)]
    CombinePublicKey(#[from] CombinePublicKeysError),
}
