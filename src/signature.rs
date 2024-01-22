//! Implementation of the verification of the signature

use super::{
    byte_array::ByteArray,
    hashing::{HashError, RecursiveHashTrait, HashableMessage},
};
use super::{
    direct_trust::{DirectTrustError, Keystore},
    openssl_wrapper::{verify, OpensslError},
};
use thiserror::Error;

/// Verification of the signature according to the specification of Swiss Post
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
        error: OpensslError,
        action: String,
    },
    #[error("Time is not valide for certificate: {0}")]
    Time(String),
    #[error(transparent)]
    Hash(HashError),
    #[error("Certificate Authority {0} is unknown")]
    CertificateAuthority(String),
}
