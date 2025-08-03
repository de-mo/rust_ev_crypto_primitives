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

use crate::{
    basic_crypto_functions::{sign as openssl_sign, verify, BasisCryptoError},
    byte_array::ByteArray,
    direct_trust::{DirectTrustError, Keystore},
    hashing::{HashError, HashableMessage, RecursiveHashTrait},
};
use thiserror::Error;

#[derive(Error, Debug)]
#[error(transparent)]
/// Error with signature
pub struct SignatureError(#[from] SignatureErrorRepr);

#[derive(Error, Debug)]
enum SignatureErrorRepr {
    #[error("Error verifiying the signature")]
    VerifySignatureError { source: SignatureInternalError },
    #[error("Error signing")]
    SignError { source: SignatureInternalError },
}

/*
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
 */

#[derive(Error, Debug)]
enum SignatureInternalError {
    #[error("Error getting the direct_trust certificate from the keystore")]
    DTCertificate { source: DirectTrustError },
    #[error("Error getting the valid time of the direct_trust certificate")]
    GetTime { source: BasisCryptoError },
    #[error("Time is not valide for certificate: {0}")]
    Time(String),
    #[error("Error getting the public key from the direct_trust certificate")]
    PublicKey { source: BasisCryptoError },
    #[error("Error hashing message")]
    HashMessage { source: HashError },
    #[error("Error hashing additional content")]
    HashAddContent { source: HashError },
    #[error("Error hashing h")]
    HashH { source: HashError },
    #[error("Error verifying signature")]
    VerifySignature { source: BasisCryptoError },
    #[error("Secret key is missing")]
    MissingSecretKey,
    #[error("Error signing the message")]
    Sign { source: BasisCryptoError },
}

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
    verify_signature_impl(keystore, ca_id, message, additional_context, signature)
        .map_err(|e| SignatureErrorRepr::VerifySignatureError { source: e })
        .map_err(SignatureError::from)
}

fn verify_signature_impl(
    keystore: &Keystore,
    ca_id: &str,
    message: &HashableMessage,
    additional_context: &HashableMessage,
    signature: &ByteArray,
) -> Result<bool, SignatureInternalError> {
    // FindCertificate
    let direct_trust_certificate = keystore
        .public_certificate(ca_id)
        .map_err(|e| SignatureInternalError::DTCertificate { source: e })?;
    let cert = direct_trust_certificate.signing_certificate();

    // Validate Time
    let time_ok = cert
        .is_valid_time()
        .map_err(|e| SignatureInternalError::GetTime { source: e })?;
    if !time_ok {
        return Err(SignatureInternalError::Time(ca_id.to_string()));
    }

    // Get public key
    let pkey = cert
        .public_key()
        .map_err(|e| SignatureInternalError::PublicKey { source: e })?;

    // Calculate hash
    // Precalulate hash of message and additional_context to avoid problem with lifetimes
    let h_vec = vec![
        HashableMessage::Hashed(
            message
                .recursive_hash()
                .map_err(|e| SignatureInternalError::HashMessage { source: e })?,
        ),
        HashableMessage::Hashed(
            additional_context
                .recursive_hash()
                .map_err(|e| SignatureInternalError::HashAddContent { source: e })?,
        ),
    ];
    let h = HashableMessage::from(h_vec)
        .recursive_hash()
        .map_err(|e| SignatureInternalError::HashH { source: e })?;

    // Verify signature
    verify(&pkey, &h, signature).map_err(|e| SignatureInternalError::VerifySignature { source: e })
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
    sign_impl(keystore, message, additional_context)
        .map_err(|e| SignatureErrorRepr::SignError { source: e })
        .map_err(SignatureError::from)
}

fn sign_impl(
    keystore: &Keystore,
    message: &HashableMessage,
    additional_context: &HashableMessage,
) -> Result<ByteArray, SignatureInternalError> {
    // get secret key and certificate to sign
    let direct_trust_certificate = keystore
        .secret_key_certificate()
        .map_err(|e| SignatureInternalError::DTCertificate { source: e })?;
    let cert = direct_trust_certificate.signing_certificate();

    // Validate Time
    let time_ok = cert
        .is_valid_time()
        .map_err(|e| SignatureInternalError::GetTime { source: e })?;
    if !time_ok {
        return Err(SignatureInternalError::Time(cert.authority().to_owned()));
    }

    let pk_private = cert
        .secret_key()
        .as_ref()
        .ok_or(SignatureInternalError::MissingSecretKey)?;

    // Calculate hash
    // Precalulate hash of message and additional_context to avoid problem with lifetimes
    let h_vec = vec![
        HashableMessage::Hashed(
            message
                .recursive_hash()
                .map_err(|e| SignatureInternalError::HashMessage { source: e })?,
        ),
        HashableMessage::Hashed(
            additional_context
                .recursive_hash()
                .map_err(|e| SignatureInternalError::HashAddContent { source: e })?,
        ),
    ];
    let h = HashableMessage::from(h_vec)
        .recursive_hash()
        .map_err(|e| SignatureInternalError::HashH { source: e })?;

    // Verify signature
    openssl_sign(pk_private, &h).map_err(|e| SignatureInternalError::Sign { source: e })
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
