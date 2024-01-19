//! Implementation of the verification of the signature of an object
//!
//! The trait [VerifiySignatureTrait] is used to verify the signature

use super::{byte_array::ByteArray, hashing::HashableMessage};
use super::{
    direct_trust::{DirectTrustError, Keystore},
    openssl_wrapper::{verify, OpensslError},
};
use thiserror::Error;

/// Trait that must be implemented for each object implementing a signature to be verified
///
/// The following function are to be implemented for the object to make it running:
/// - [VerifiySignatureTrait::get_hashable] Get the [HashableMessage] for the object
/// - [VerifiySignatureTrait::get_context_data] Get the context data as [HashableMessage] for the object, according to the specifications
/// - [VerifiySignatureTrait::get_certificate_authority] Certificate Authority of the certificate to fin the certificate in the keystore
/// - [VerifiySignatureTrait::get_signature] Get the signature of the object
pub trait VerifiySignatureTrait<'a>
where
    Self: 'a,
{
    type Error: std::fmt::Debug;

    /// Get the hashable from the object
    fn get_hashable(&'a self) -> Result<HashableMessage<'a>, Self::Error>;

    /// Get the context data of the object according to the specifications
    fn get_context_data(&'a self) -> Vec<HashableMessage<'a>>;

    /// Get the Certificate Authority to the specifications
    fn get_certificate_authority(&self) -> Result<String, Self::Error>;

    /// Get the signature of the object
    fn get_signature(&self) -> ByteArray;

    /// Get the context data of the object according to the context data
    fn get_context_hashable(&'a self) -> HashableMessage {
        if self.get_context_data().len() == 1 {
            return self.get_context_data()[0].clone();
        }
        HashableMessage::from(self.get_context_data())
    }

    /// Verfiy the signature according to the specifications of Verifier
    fn verifiy_signature(&'a self, keystore: &Keystore) -> Result<bool, SignatureError> {
        let ca = &self
            .get_certificate_authority()
            .map_err(|e| SignatureError::CertificateAuthority(format!("{:?}", e)))?;
        let dtc = keystore.certificate(ca).map_err(SignatureError::Keystore)?;
        let cert = dtc.signing_certificate();
        //dt.signing_certificate();
        let time_ok = cert
            .is_valid_time()
            .map_err(|e| SignatureError::Certificate {
                name: ca.to_string(),
                error: e,
                action: "validating time".to_string(),
            })?;
        if !time_ok {
            return Err(SignatureError::Time(ca.to_string()));
        }
        let pkey = cert
            .get_public_key()
            .map_err(|e| SignatureError::Certificate {
                name: ca.to_string(),
                error: e,
                action: "reading public key".to_string(),
            })?;
        let hashable = self
            .get_hashable()
            .map_err(|e| SignatureError::Hash(format!("{:?}", e)))?;
        verify(
            pkey.pkey_public().as_ref(),
            &hashable,
            &self.get_context_hashable(),
            &self.get_signature(),
        )
        .map_err(|e| SignatureError::Certificate {
            name: ca.to_string(),
            error: e,
            action: "verifyinh signature".to_string(),
        })
    }
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
    #[error("Error hashing the structure: {0}")]
    Hash(String),
    #[error("Certificate Authority {0} is unknown")]
    CertificateAuthority(String),
}
