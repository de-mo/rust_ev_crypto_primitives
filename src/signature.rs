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

//! Implementation of the verification of the signature

use super::{
    basic_crypto_functions::{verify, BasisCryptoError},
    direct_trust::{DirectTrustError, Keystore},
};
use super::{
    byte_array::ByteArray,
    hashing::{HashError, HashableMessage, RecursiveHashTrait},
};
use thiserror::Error;

/// Verification of the signature according to the specification of Swiss Post (Algorithm 7.3)
///
/// # Error
/// Return a [SignatureError] if something going wrong during the verification
pub fn verify_signature(
    keystore: &Keystore,
    ca_id: &str,
    message: &HashableMessage,
    additional_context: &HashableMessage,
    signature: &ByteArray,
) -> Result<bool, SignatureError> {
    // FindCertificate
    let direct_trust_certificate = keystore
        .certificate(ca_id)
        .map_err(SignatureError::Keystore)?;
    let cert = direct_trust_certificate.signing_certificate();

    // Validate Time
    let time_ok = cert
        .is_valid_time()
        .map_err(|e| SignatureError::Certificate {
            name: ca_id.to_string(),
            error: e,
            action: "validating time".to_string(),
        })?;
    if !time_ok {
        return Err(SignatureError::Time(ca_id.to_string()));
    }

    // Get public key
    let pkey = cert
        .get_public_key()
        .map_err(|e| SignatureError::Certificate {
            name: ca_id.to_string(),
            error: e,
            action: "reading public key".to_string(),
        })?;
    let pub_key = pkey.pkey_public().as_ref();

    // Calculate hash
    let h = HashableMessage::from(vec![message.to_owned(), additional_context.to_owned()])
        .try_hash()
        .map_err(SignatureError::Hash)?;

    // Verify signature
    verify(pub_key, &h, signature).map_err(|e| SignatureError::Certificate {
        name: ca_id.to_string(),
        error: e,
        action: "verifying signature".to_string(),
    })
}

// Enum representing the errors validating the signature
#[derive(Error, Debug)]
pub enum SignatureError {
    #[error(transparent)]
    Keystore(DirectTrustError),
    #[error("Error of certificate {name} during {action}: {error}")]
    Certificate {
        name: String,
        error: BasisCryptoError,
        action: String,
    },
    #[error("Time is not valide for certificate: {0}")]
    Time(String),
    #[error(transparent)]
    Hash(HashError),
    #[error("Certificate Authority {0} is unknown")]
    CertificateAuthority(String),
}
