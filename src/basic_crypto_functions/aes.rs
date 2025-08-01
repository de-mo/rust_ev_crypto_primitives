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

use super::{BasisCryptoError, BasisCryptoErrorRepr};
use crate::ByteArray;
use openssl::{
    error::ErrorStack,
    symm::{Cipher, Crypter as OpenSSLCrypter, Mode},
};
use thiserror::Error;

pub const CRYPTER_TAG_SIZE: usize = 16;

#[derive(Error, Debug)]
pub(super) enum InternalStepError {
    #[error("Error creating crypter")]
    CreateCypher { source: ErrorStack },
    #[error("Error setting the tag")]
    SetTag { source: ErrorStack },
    #[error("Error getting the tag")]
    GetTag { source: ErrorStack },
    #[error("Error updating the crypter")]
    Update { source: ErrorStack },
    #[error("Error finalizing the crypter")]
    Finalize { source: ErrorStack },
    #[error("Error updating aad crypter")]
    UpdateAadCrypter { source: ErrorStack },
}

#[derive(Error, Debug)]
pub(super) enum AESError {
    #[error("Error new")]
    New { source: InternalStepError },
}

/// Structure to decrypt part to part a cipher encrypted with AES GCM n Padding
struct Crypter {
    encryption_key: Vec<u8>,
    aad: Vec<u8>,
    nonce: Vec<u8>,
    block_size: usize,
    crypter: Option<OpenSSLCrypter>,
}

pub struct Decrypter(Crypter);
pub struct Encrypter(Crypter);

impl Decrypter {
    /// New Decrypter
    pub fn new(
        nonce: &ByteArray,
        encryption_key: &ByteArray,
        aad: &ByteArray,
    ) -> Result<Self, BasisCryptoError> {
        Ok(Self(Crypter::new(
            nonce,
            encryption_key,
            aad,
            Mode::Decrypt,
        )?))
    }

    /// Decrypt the input
    ///
    /// The tag must not be part of the input
    ///
    /// Return a ByteArray with the plaintext or an error
    pub fn decrypt(&mut self, input: &ByteArray) -> Result<ByteArray, BasisCryptoError> {
        let data_len = input.len();
        let mut plaintext = vec![0; data_len + self.0.block_size];
        let count = self
            .0
            .crypter_mut()
            .update(input.to_bytes(), &mut plaintext)
            .map_err(|e| InternalStepError::Update { source: e })
            .map_err(|e| AESError::New { source: e })
            .map_err(BasisCryptoErrorRepr::from)?;
        plaintext.truncate(count);
        Ok(ByteArray::from_bytes(&plaintext))
    }

    /// Decrypt the input
    ///
    /// The tag is part of the inputs
    ///
    /// Return a ByteArray with the plaintext or an error
    pub fn decrypt_and_finalize_with_tag(
        &mut self,
        input: &ByteArray,
    ) -> Result<ByteArray, BasisCryptoError> {
        if input.len() < CRYPTER_TAG_SIZE {
            return Err(BasisCryptoError::from(BasisCryptoErrorRepr::TooSmallInput));
        }
        let (c_slice, tag_slice) = &input.to_bytes().split_at(input.len() - CRYPTER_TAG_SIZE);
        let ciphertext = ByteArray::from(&c_slice.to_vec());
        let tag = ByteArray::from(&tag_slice.to_vec());
        let plaintext = self.decrypt(&ciphertext)?;
        let crypter = self.0.crypter_mut();
        crypter
            .set_tag(tag.to_bytes())
            .map_err(|e| InternalStepError::SetTag { source: e })
            .map_err(|e| AESError::New { source: e })
            .map_err(BasisCryptoErrorRepr::from)?;
        let mut final_buf = vec![0; CRYPTER_TAG_SIZE];
        let count = crypter
            .finalize(&mut final_buf)
            .map_err(|e| InternalStepError::Finalize { source: e })
            .map_err(|e| AESError::New { source: e })
            .map_err(BasisCryptoErrorRepr::from)?;
        final_buf.truncate(count);
        Ok(plaintext.new_append(&ByteArray::from(&final_buf)))
    }
}

impl Encrypter {
    /// New Encrypter
    pub fn new(
        nonce: &ByteArray,
        encryption_key: &ByteArray,
        aad: &ByteArray,
    ) -> Result<Self, BasisCryptoError> {
        Ok(Self(Crypter::new(
            nonce,
            encryption_key,
            aad,
            Mode::Encrypt,
        )?))
    }

    /// Decrypt the input
    ///
    /// The tag will not be delivered with the output
    ///
    /// Return a ByteArray with the plaintext or an error
    pub fn encrypt(&mut self, input: &ByteArray) -> Result<ByteArray, BasisCryptoError> {
        let data_len = input.len();
        let mut ciphertext = vec![0; data_len + self.0.block_size];
        let count = self
            .0
            .crypter_mut()
            .update(input.to_bytes(), &mut ciphertext)
            .map_err(|e| InternalStepError::Update { source: e })
            .map_err(|e| AESError::New { source: e })
            .map_err(BasisCryptoErrorRepr::from)?;
        ciphertext.truncate(count);
        Ok(ByteArray::from_bytes(&ciphertext))
    }

    /// Decrypt the input
    ///
    /// The tag is part of the output
    ///
    /// Return a ByteArray with the ciphertext and the tag at the end or an error
    pub fn encrypt_and_finalize_with_tag(
        &mut self,
        input: &ByteArray,
    ) -> Result<ByteArray, BasisCryptoError> {
        let ciphertext = self.encrypt(input)?;
        let crypter = self.0.crypter_mut();
        let mut final_buf = vec![0; CRYPTER_TAG_SIZE];
        let count = crypter
            .finalize(&mut final_buf)
            .map_err(|e| InternalStepError::Finalize { source: e })
            .map_err(|e| AESError::New { source: e })
            .map_err(BasisCryptoErrorRepr::from)?;
        final_buf.truncate(count);
        let mut tag = vec![0; CRYPTER_TAG_SIZE];
        crypter
            .get_tag(&mut tag)
            .map_err(|e| InternalStepError::GetTag { source: e })
            .map_err(|e| AESError::New { source: e })
            .map_err(BasisCryptoErrorRepr::from)?;
        Ok(ciphertext
            .new_append(&ByteArray::from(&final_buf))
            .new_append(&ByteArray::from(&tag)))
    }
}

impl Crypter {
    /// New Crypter
    pub fn new(
        nonce: &ByteArray,
        encryption_key: &ByteArray,
        aad: &ByteArray,
        mode: Mode,
    ) -> Result<Self, BasisCryptoError> {
        let mut res = Self {
            nonce: nonce.to_bytes().to_vec(),
            encryption_key: encryption_key.to_bytes().to_vec(),
            aad: aad.to_bytes().to_vec(),
            block_size: Self::cipher().block_size(),
            crypter: None,
        };
        res.crypter = Some(
            res.generate_crypter(mode)
                .map_err(|e| AESError::New { source: e })
                .map_err(BasisCryptoErrorRepr::from)?,
        );
        Ok(res)
    }

    fn cipher() -> Cipher {
        Cipher::aes_256_gcm()
    }

    fn crypter_mut(&mut self) -> &mut OpenSSLCrypter {
        self.crypter.as_mut().unwrap()
    }

    fn generate_crypter(&self, mode: Mode) -> Result<OpenSSLCrypter, InternalStepError> {
        let mut crypter = OpenSSLCrypter::new(
            Self::cipher(),
            mode,
            self.encryption_key.as_slice(),
            Some(&self.nonce),
        )
        .map_err(|e| InternalStepError::CreateCypher { source: e })?;
        crypter.pad(false);
        crypter
            .aad_update(&self.aad)
            .map_err(|e| InternalStepError::UpdateAadCrypter { source: e })?;
        Ok(crypter)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_new_decrypter() {
        let nonce: Vec<u8> = vec![52, 51, 51, 68, 54, 66, 52, 65, 65, 56, 52, 50];
        let derive_key: Vec<u8> = vec![
            110, 227, 223, 116, 214, 30, 72, 61, 226, 111, 134, 191, 126, 5, 220, 151, 74, 72, 110,
            168, 123, 251, 43, 90, 148, 76, 64, 38, 174, 26, 176, 157,
        ];
        Decrypter::new(
            &ByteArray::from(&nonce),
            &ByteArray::from(&derive_key),
            &ByteArray::default(),
        )
        .unwrap();
    }

    #[test]
    fn test_new_encrypter() {
        let nonce: Vec<u8> = vec![52, 51, 51, 68, 54, 66, 52, 65, 65, 56, 52, 50];
        let derive_key: Vec<u8> = vec![
            110, 227, 223, 116, 214, 30, 72, 61, 226, 111, 134, 191, 126, 5, 220, 151, 74, 72, 110,
            168, 123, 251, 43, 90, 148, 76, 64, 38, 174, 26, 176, 157,
        ];
        Encrypter::new(
            &ByteArray::from(&nonce),
            &ByteArray::from(&derive_key),
            &ByteArray::default(),
        )
        .unwrap();
    }
}
