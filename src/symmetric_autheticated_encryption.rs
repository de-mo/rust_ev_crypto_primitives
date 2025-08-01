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

//! Symmetric authenticated encrpytion methods according to the specifications

/// The size of the nonce for the authenticated encryption
pub const AUTH_ENCRPYTION_NONCE_SIZE: usize = 12;

use crate::{
    basic_crypto_functions::{BasisCryptoError, Decrypter, Encrypter},
    random::random_bytes,
    ByteArray,
};
use thiserror::Error;

/// Errors with symmetric authenticated encrpytion
#[derive(Error, Debug)]
#[error(transparent)]
pub struct SymAuthenticatedEncryptionError(#[from] SymAuthenticatedEncryptionErrorRepr);

#[derive(Error, Debug)]
enum SymAuthenticatedEncryptionErrorRepr {
    #[error("Error creating the decrypter")]
    NewDecrypter { source: BasisCryptoError },
    #[error("Error getting the plaintext")]
    GetPlaintextSymmetric { source: BasisCryptoError },
    #[error("Error generating the random nonce")]
    RandomNonce { source: BasisCryptoError },
    #[error("Error creating the encrypter")]
    NewEncrypter { source: BasisCryptoError },
    #[error("Error generating the ciphertext")]
    GenCiphertextSymmetric { source: BasisCryptoError },
    #[error("The associated data at position {position} has a length of {length} with is bigger than 255")]
    AssocitedDataLength { position: usize, length: usize },
}

/// Decrypt structure to store the informations for the method GetPlaintextSymmetric
pub struct AuthenticatedEncryptionDecrypt {
    decrypter: Decrypter,
}

fn collect_associated_data(
    associated_data: &[String],
) -> Result<ByteArray, SymAuthenticatedEncryptionErrorRepr> {
    associated_data
        .iter()
        .enumerate()
        .try_fold(ByteArray::default(), |acc, (i, a)| {
            if a.len() > 255 {
                return Err(SymAuthenticatedEncryptionErrorRepr::AssocitedDataLength {
                    position: i,
                    length: a.len(),
                });
            }
            Ok(acc
                .new_append(&ByteArray::from(&vec![a.len() as u8]))
                .new_append(&ByteArray::from(a.as_str())))
        })
}

impl AuthenticatedEncryptionDecrypt {
    /// New decrypt structure
    ///
    /// Data according the the specifications of Swiss Post (GetPlaintextSymmetric)
    pub fn new(
        encryption_key: &ByteArray,
        nonce: &ByteArray,
        associated_data: &[String],
    ) -> Result<Self, SymAuthenticatedEncryptionError> {
        let aad = collect_associated_data(associated_data)?;
        Ok(Self {
            decrypter: Decrypter::new(nonce, encryption_key, &aad)
                .map_err(|e| SymAuthenticatedEncryptionErrorRepr::NewDecrypter { source: e })?,
        })
    }

    /// Algorithm 6.2
    pub fn get_plaintext_symmetric(
        &mut self,
        ciphertext: &ByteArray,
    ) -> Result<ByteArray, SymAuthenticatedEncryptionError> {
        self.decrypter
            .decrypt(ciphertext)
            .map_err(|e| SymAuthenticatedEncryptionErrorRepr::GetPlaintextSymmetric { source: e })
            .map_err(SymAuthenticatedEncryptionError::from)
    }
}

/// Encrypt structure to store the informations for the method GenCiphertextSymmetric
pub struct AuthenticatedEncryptionEncrypt {
    nonce: ByteArray,
    encrypter: Encrypter,
}

impl AuthenticatedEncryptionEncrypt {
    /// New decrypt structure
    ///
    /// Data according the the specifications of Swiss Post (GenCiphertextSymmetric)
    pub fn new(
        encryption_key: &ByteArray,
        associated_data: &[String],
        nonce: Option<&ByteArray>,
    ) -> Result<Self, SymAuthenticatedEncryptionError> {
        let nonce = match nonce {
            Some(n) => n.clone(),
            None => random_bytes(AUTH_ENCRPYTION_NONCE_SIZE)
                .map_err(|e| SymAuthenticatedEncryptionErrorRepr::RandomNonce { source: e })?,
        };
        let aad = collect_associated_data(associated_data)?;
        Ok(Self {
            nonce: nonce.clone(),
            encrypter: Encrypter::new(&nonce, encryption_key, &aad)
                .map_err(|e| SymAuthenticatedEncryptionErrorRepr::NewEncrypter { source: e })?,
        })
    }

    /// Get the generated nonce
    pub fn nonce(&self) -> &ByteArray {
        &self.nonce
    }

    /// Algorithm 6.1
    pub fn gen_ciphertext_symmetric(
        &mut self,
        plaintext: &ByteArray,
    ) -> Result<ByteArray, SymAuthenticatedEncryptionError> {
        self.encrypter
            .encrypt(plaintext)
            .map_err(|e| SymAuthenticatedEncryptionErrorRepr::GenCiphertextSymmetric { source: e })
            .map_err(SymAuthenticatedEncryptionError::from)
    }
}

#[cfg(test)]
mod test {
    use crate::test_json_data::{
        get_test_cases_from_json_file, json_64_value_to_byte_array,
        json_array_value_to_array_string,
    };

    use super::*;

    #[test]
    fn test_get_plaintext_symmetric() {
        for tc in get_test_cases_from_json_file("symmetric", "get-plaintext-symmetric.json") {
            let encryption_key = json_64_value_to_byte_array(&tc["input"]["encryption_key"]);
            let ciphertext = json_64_value_to_byte_array(&tc["input"]["ciphertext"]);
            let nonce = json_64_value_to_byte_array(&tc["input"]["nonce"]);
            let associated_data = json_array_value_to_array_string(&tc["input"]["associated_data"]);
            let mut decrypter =
                AuthenticatedEncryptionDecrypt::new(&encryption_key, &nonce, &associated_data)
                    .unwrap();
            let plaintext_res = decrypter.get_plaintext_symmetric(&ciphertext);
            assert!(
                plaintext_res.is_ok(),
                "Error unwrapping plaintext in {}: {}",
                &tc["description"],
                plaintext_res.unwrap_err()
            );
            let mut plaintext = plaintext_res.unwrap();
            let expected = json_64_value_to_byte_array(&tc["output"]["plaintext"]);
            plaintext.truncate(expected.len());
            assert_eq!(plaintext, expected, "{}", &tc["description"])
        }
    }

    #[test]
    fn test_gen_ciphertext_symmetric() {
        for tc in get_test_cases_from_json_file("symmetric", "gen-ciphertext-symmetric.json") {
            let encryption_key = json_64_value_to_byte_array(&tc["input"]["encryption_key"]);
            let plaintext = json_64_value_to_byte_array(&tc["input"]["plaintext"]);
            let nonce = json_64_value_to_byte_array(&tc["output"]["nonce"]);
            let associated_data = json_array_value_to_array_string(&tc["input"]["associated_data"]);
            let mut encrypter = AuthenticatedEncryptionEncrypt::new(
                &encryption_key,
                &associated_data,
                Some(&nonce),
            )
            .unwrap();
            let ciphertext_res = encrypter.gen_ciphertext_symmetric(&plaintext);
            assert!(
                ciphertext_res.is_ok(),
                "Error unwrapping ciphertext in {}: {}",
                &tc["description"],
                ciphertext_res.unwrap_err()
            );
            let ciphertext = ciphertext_res.unwrap();
            let mut expected = json_64_value_to_byte_array(&tc["output"]["ciphertext"]);
            expected.truncate(ciphertext.len());
            assert_eq!(ciphertext, expected, "{}", &tc["description"])
        }
    }

    #[test]
    fn test_encrypt_decrypt() {
        for tc in get_test_cases_from_json_file("symmetric", "gen-ciphertext-symmetric.json") {
            let encryption_key = json_64_value_to_byte_array(&tc["input"]["encryption_key"]);
            let plaintext = json_64_value_to_byte_array(&tc["input"]["plaintext"]);
            let associated_data = json_array_value_to_array_string(&tc["input"]["associated_data"]);
            let mut encrypter =
                AuthenticatedEncryptionEncrypt::new(&encryption_key, &associated_data, None)
                    .unwrap();
            let ciphertext = encrypter.gen_ciphertext_symmetric(&plaintext).unwrap();
            let nonce = encrypter.nonce();
            let mut decrypter =
                AuthenticatedEncryptionDecrypt::new(&encryption_key, nonce, &associated_data)
                    .unwrap();
            let plaintext_res = decrypter.get_plaintext_symmetric(&ciphertext).unwrap();
            assert_eq!(plaintext_res, plaintext, "{}", &tc["description"])
        }
    }
}
