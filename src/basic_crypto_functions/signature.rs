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

//! Implement necessary signature functions for the crate

use super::{super::byte_array::ByteArray, BasisCryptoError};
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, PKeyRef, Private, Public},
    rsa::Padding,
    sign::{RsaPssSaltlen, Signer, Verifier},
};

/// Verify the signature using RSASSA-PSS as a signature algorithm
///
/// SHA-256 is used as the underlying hash function and hash for the mask generation function.
/// The mask generation function used for PSS is MGF1, defined in appendix B.2 of RFC8017.
/// The length of the salt is set to the length of the underlying hash function (i.e. 32 bytes).
/// The trailer field number is 1, which represents the trailer field with value 0xbc, in accordance with the same RFC.
pub fn verify(
    pkey: &PKeyRef<Public>,
    hashed: &ByteArray,
    signature: &ByteArray,
) -> Result<bool, BasisCryptoError> {
    // With the next two lines, it is sure that the certificate is recognized as SRA certificate from openssl
    let pkey_temp = PKey::from_rsa(pkey.rsa().map_err(|e| BasisCryptoError::PublicKeyError {
        msg: "Error in pkey.rsa".to_string(),
        source: e,
    })?)
    .map_err(|e| BasisCryptoError::PublicKeyError {
        msg: "Error in PKey::from_rsa".to_string(),
        source: e,
    })?;
    let rsa_pkey = pkey_temp.as_ref();
    let mut verifier = Verifier::new(MessageDigest::sha256(), rsa_pkey).map_err(|e| {
        BasisCryptoError::SignatureVerify {
            msg: "Error creating Sign Verifier".to_string(),
            source: e,
        }
    })?;
    // Necessary for the next functions
    verifier.set_rsa_padding(Padding::PKCS1_PSS).map_err(|e| {
        BasisCryptoError::SignatureVerify {
            msg: "Error set_rsa_padding".to_string(),
            source: e,
        }
    })?;
    verifier
        .set_rsa_mgf1_md(MessageDigest::sha256())
        .map_err(|e| BasisCryptoError::SignatureVerify {
            msg: "Error set_rsa_mgf1_md".to_string(),
            source: e,
        })?;
    verifier
        .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
        .map_err(|e| BasisCryptoError::SignatureVerify {
            msg: "Error set_rsa_pss_saltlen".to_string(),
            source: e,
        })?;
    verifier
        .verify_oneshot(signature.to_bytes(), hashed.to_bytes())
        .map_err(|e| BasisCryptoError::SignatureVerify {
            msg: "Error verify_oneshot".to_string(),
            source: e,
        })
}

/// Sign using RSASSA-PSS as a signature algorithm
///
/// SHA-256 is used as the underlying hash function and hash for the mask generation function.
/// The mask generation function used for PSS is MGF1, defined in appendix B.2 of RFC8017.
/// The length of the salt is set to the length of the underlying hash function (i.e. 32 bytes).
/// The trailer field number is 1, which represents the trailer field with value 0xbc, in accordance with the same RFC.
pub fn sign(skey: &PKeyRef<Private>, hashed: &ByteArray) -> Result<ByteArray, BasisCryptoError> {
    // With the next two lines, it is sure that the certificate is recognized as SRA certificate from openssl
    let pkey_temp = PKey::from_rsa(skey.rsa().map_err(|e| BasisCryptoError::PublicKeyError {
        msg: "Error in pkey.rsa".to_string(),
        source: e,
    })?)
    .map_err(|e| BasisCryptoError::PublicKeyError {
        msg: "Error in PKey::from_rsa".to_string(),
        source: e,
    })?;
    let rsa_pkey = pkey_temp.as_ref();
    let mut signer =
        Signer::new(MessageDigest::sha256(), rsa_pkey).map_err(|e| BasisCryptoError::Sign {
            msg: "Error creating Signer".to_string(),
            source: e,
        })?;
    // Necessary for the next functions
    signer
        .set_rsa_padding(Padding::PKCS1_PSS)
        .map_err(|e| BasisCryptoError::Sign {
            msg: "Error set_rsa_padding".to_string(),
            source: e,
        })?;
    signer
        .set_rsa_mgf1_md(MessageDigest::sha256())
        .map_err(|e| BasisCryptoError::Sign {
            msg: "Error set_rsa_mgf1_md".to_string(),
            source: e,
        })?;
    signer
        .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
        .map_err(|e| BasisCryptoError::Sign {
            msg: "Error set_rsa_pss_saltlen".to_string(),
            source: e,
        })?;
    signer
        .update(hashed.to_bytes())
        .map_err(|e| BasisCryptoError::Sign {
            msg: "Error updating the signer".to_string(),
            source: e,
        })?;
    let signature = signer.sign_to_vec().map_err(|e| BasisCryptoError::Sign {
        msg: "Error verify_oneshot".to_string(),
        source: e,
    })?;
    Ok(ByteArray::from_bytes(&signature))
}
