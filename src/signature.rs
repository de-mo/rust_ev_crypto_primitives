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
    basic_crypto_functions::{sign as openssl_sign, verify, BasisCryptoError},
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
        .public_certificate(ca_id)
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
    let pkey = cert.public_key().map_err(|e| SignatureError::Certificate {
        name: ca_id.to_string(),
        error: e,
        action: "reading public key".to_string(),
    })?;
    let pub_key = pkey.pkey_public().as_ref();

    // Calculate hash
    let h = HashableMessage::from(vec![message.to_owned(), additional_context.to_owned()])
        .recursive_hash()
        .map_err(SignatureError::Hash)?;

    // Verify signature
    verify(pub_key, &h, signature).map_err(|e| SignatureError::Certificate {
        name: ca_id.to_string(),
        error: e,
        action: "verifying signature".to_string(),
    })
}

/// Sign the message according to the specification of Swiss Post (Algorithm 7.3)
///
/// # Error
/// Return a [SignatureError] if something going wrong during the verification
pub fn sign(
    keystore: &Keystore,
    message: &HashableMessage,
    additional_context: &HashableMessage,
) -> Result<ByteArray, SignatureError> {
    // get secret key and certificate to sign
    let direct_trust_certificate = keystore
        .secret_key_certificate()
        .map_err(SignatureError::Keystore)?;
    let cert = direct_trust_certificate.signing_certificate();

    // Validate Time
    let time_ok = cert
        .is_valid_time()
        .map_err(|e| SignatureError::Certificate {
            name: cert.authority().to_owned(),
            error: e,
            action: "validating time".to_string(),
        })?;
    if !time_ok {
        return Err(SignatureError::Time(cert.authority().to_owned()));
    }

    let pk_private = cert
        .secret_key()
        .as_ref()
        .ok_or(SignatureError::MissingSecretKey)?
        .pkey_private();

    // Calculate hash
    let h = HashableMessage::from(vec![message.to_owned(), additional_context.to_owned()])
        .recursive_hash()
        .map_err(SignatureError::Hash)?;

    // Verify signature
    let res = openssl_sign(pk_private, &h).map_err(|e| SignatureError::Certificate {
        name: cert.authority().to_owned(),
        error: e,
        action: "Signing".to_string(),
    })?;
    Ok(res)
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
    #[error("Secret key is missing")]
    MissingSecretKey,
    #[error("Time is not valide for certificate: {0}")]
    Time(String),
    #[error(transparent)]
    Hash(HashError),
    #[error("Certificate Authority {0} is unknown")]
    CertificateAuthority(String),
}

#[cfg(test)]
mod test {
    use super::*;
    use std::path::{Path, PathBuf};

    const VERIFIER_KEYSTORE_FILE_NAME: &str = "public_keys_keystore_verifier.p12";
    const VERIFIER_PASSWORD_FILE_NAME: &str = "public_keys_keystore_verifier_pw.txt";
    const CANTON_KEYSTORE_FILE_NAME: &str = "signing_keystore_canton.p12";
    const CANTON_PASSWORD_FILE_NAME: &str = "signing_pw_canton.txt";

    fn get_location() -> PathBuf {
        Path::new("./").join("test_data").join("direct-trust")
    }

    fn get_verifier_keystore() -> Keystore {
        Keystore::from_pkcs12(
            &get_location().join(Path::new(VERIFIER_KEYSTORE_FILE_NAME)),
            &get_location().join(Path::new(VERIFIER_PASSWORD_FILE_NAME)),
        )
        .unwrap()
    }

    fn get_canton_keystore() -> Keystore {
        Keystore::from_pkcs12(
            &get_location().join(Path::new(CANTON_KEYSTORE_FILE_NAME)),
            &get_location().join(Path::new(CANTON_PASSWORD_FILE_NAME)),
        )
        .unwrap()
    }

    #[test]
    fn test_create_pkcs12() {
        let m = HashableMessage::from("test");
        let s = HashableMessage::from("addtional context");
        let v_ks = get_verifier_keystore();
        let c_ks = get_canton_keystore();
        let signature_res = sign(&c_ks, &m, &s);
        assert!(signature_res.is_ok());
        let signature = signature_res.unwrap();
        let verify_res = verify_signature(&v_ks, "canton", &m, &s, &signature);
        assert!(verify_res.is_ok());
        assert!(verify_res.unwrap());
    }
}
