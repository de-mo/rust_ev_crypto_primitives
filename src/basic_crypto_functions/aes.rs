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

use super::BasisCryptoError;
use crate::ByteArray;
use openssl::symm::{Cipher, Crypter, Mode};

/// Structure to decrypt part to part a cipher encrypted with AES GCM n Padding
pub struct Decrypter {
    nonce: Vec<u8>,
    encryption_key: Vec<u8>,
    block_size: usize,
    crypter: Option<Crypter>,
}

impl Decrypter {
    /// New Decrypter
    pub fn new(nonce: &ByteArray, encryption_key: &ByteArray) -> Result<Self, BasisCryptoError> {
        let mut res = Self {
            nonce: nonce.to_bytes().to_vec(),
            encryption_key: encryption_key.to_bytes().to_vec(),
            block_size: Self::cipher().block_size(),
            crypter: None,
        };
        res.crypter = Some(res.generate_crypter()?);
        Ok(res)
    }

    /// Decrypt the input
    ///
    /// Return a ByteArray with the plaintext or an error
    pub fn decrypt(&mut self, input: &ByteArray) -> Result<ByteArray, BasisCryptoError> {
        let data_len = input.len();
        let mut plaintext = vec![0; data_len + self.block_size];
        let count = self
            .crypter_mut()
            .update(&input.to_bytes(), &mut plaintext)
            .map_err(|e| BasisCryptoError::AesGcmError {
                msg: "Updating crypter".to_string(),
                source: e,
            })?;
        plaintext.truncate(count);
        Ok(ByteArray::from_bytes(&plaintext))
    }

    fn cipher() -> Cipher {
        Cipher::aes_256_gcm()
    }

    fn crypter_mut(&mut self) -> &mut Crypter {
        self.crypter.as_mut().unwrap()
    }

    fn generate_crypter(&self) -> Result<Crypter, BasisCryptoError> {
        let mut crypter = Crypter::new(
            Self::cipher(),
            Mode::Decrypt,
            self.encryption_key.as_slice(),
            Some(&self.nonce),
        )
        .map_err(|e| BasisCryptoError::AesGcmError {
            msg: "Creating crytper".to_string(),
            source: e,
        })?;
        crypter.pad(false);
        crypter
            .aad_update(vec![].as_slice())
            .map_err(|e| BasisCryptoError::AesGcmError {
                msg: "Updating aad".to_string(),
                source: e,
            })?;
        Ok(crypter)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_new() {
        let nonce: Vec<u8> = vec![52, 51, 51, 68, 54, 66, 52, 65, 65, 56, 52, 50];
        let derive_key: Vec<u8> = vec![
            110, 227, 223, 116, 214, 30, 72, 61, 226, 111, 134, 191, 126, 5, 220, 151, 74, 72, 110,
            168, 123, 251, 43, 90, 148, 76, 64, 38, 174, 26, 176, 157,
        ];
        Decrypter::new(&ByteArray::from(&nonce), &ByteArray::from(&derive_key)).unwrap();
    }
}
