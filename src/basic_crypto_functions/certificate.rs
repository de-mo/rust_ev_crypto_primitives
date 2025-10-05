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

//! Wrapper for Certificate functions

use super::{BasisCryptoError, BasisCryptoErrorRepr};
use crate::byte_array::ByteArray;
use openssl::{
    asn1::Asn1Time,
    error::ErrorStack,
    hash::MessageDigest,
    pkcs12::{ParsedPkcs12_2, Pkcs12},
    pkey::{PKey, Private, Public},
    x509::X509,
};
use std::{
    fmt::Display,
    fs,
    path::{Path, PathBuf},
};
use thiserror::Error;

#[derive(Error, Debug)]
pub(super) enum CertificateError {
    #[error("Creating Keystore from pkcs12 {path}")]
    FromPkcs12 {
        path: PathBuf,
        source: FromPkcs12Error,
    },
    #[error("Get Public certificate from p12")]
    GetPublicCertFromFromPkcs12(#[from] GetPublicCertFromFromPkcs12Error),
    #[error("Get Public certificate from dir")]
    GetPublicCertFromFromDir(#[from] GetPublicCertFromFromDirError),
    #[error("Creating Keystore from dir: {path} is not a directory")]
    NotDir { path: PathBuf },
    #[error("Get Private certificate in p12")]
    GetPrivateCertificate(#[from] GetPrivateCertificateError),
    #[error("Signing certificate error")]
    SigningCertificate(#[from] SigningCertificateError),
}

#[derive(Error, Debug)]
pub(super) enum FromPkcs12Error {
    #[error("Cannot read file {path}")]
    IO {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("Cannot decode p12 file {path}")]
    FromDer { path: PathBuf, source: ErrorStack },
    #[error("Cannot parse p12 file {path}")]
    Parse2 { path: PathBuf, source: ErrorStack },
}

#[derive(Error, Debug)]
pub(super) enum GetPublicCertFromFromPkcs12Error {
    #[error("The CA list ist missing in {path}")]
    MissingCAList { path: PathBuf },
    #[error("The CA {name} is missing in the list of ca of {path}")]
    MissingCA { name: String, path: PathBuf },
}

#[derive(Error, Debug)]
pub(super) enum GetPublicCertFromFromDirError {
    #[error("Cannot read file {path}")]
    IO {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("Cannot decode pem file {path}")]
    FromPem { path: PathBuf, source: ErrorStack },
}

#[derive(Error, Debug)]
pub(super) enum GetPrivateCertificateError {
    #[error("{fct} is only working for file pkc12 and not for directory format")]
    OnlyPkc12 { fct: &'static str },
    #[error("The secret key is missing in {path}")]
    KeyStoreMissingSecretKey { path: PathBuf },
    #[error("The certificate for the secret key is missing in {path}")]
    KeyStoreMissingCertSecretKey { path: PathBuf },
    #[error("Error getting the name of the secret key in {path}")]
    SecretKeyError { path: PathBuf, source: ErrorStack },
}

#[derive(Error, Debug)]
pub(super) enum SigningCertificateError {
    #[error("Error getting public key for authority {authority}")]
    CertificateErrorPK {
        authority: String,
        source: ErrorStack,
    },
    #[error("Error validating time for certificate of {authority}")]
    CertificateErrorTime {
        authority: String,
        source: ErrorStack,
    },
    #[error("Error caluclating digest for certificate of {authority}")]
    CertificateDigest {
        authority: String,
        source: ErrorStack,
    },
}

/// Keystore to collect the public keys
///
/// The keystore can be a p12 file or a directory containing the certificates
/// - In the first case, the CN of the certificates must contain the name of the authority
/// - In the second case, the certificates must contain the valid structure, the file name represent the authority
///   and the file extension is given bei [CertificateExtension] (`.cer`, or `.pem`).
pub struct Keystore {
    pcks12: Option<ParsedPkcs12_2>,
    path: PathBuf,
    extension: CertificateExtension,
}

/// Possible extension of the X509 certificate
#[derive(Clone)]
pub enum CertificateExtension {
    Cer,
    Pem,
}

/// The signing certificate
#[derive(Clone)]
pub struct SigningCertificate {
    authority: String,
    x509: X509,
    secret_key: Option<Secretkey>,
}

/// The struct contaiing the PublicKey
#[derive(Clone)]
pub struct PublicKey(PKey<Public>);

/// The struct contaiing the SecretKey
#[derive(Clone)]
pub struct Secretkey(PKey<Private>);

impl Keystore {
    /// Read the keystore from file with password to open it
    ///
    /// # Error
    /// if somwthing is going wrong
    pub fn from_pkcs12(path: &Path, password: &str) -> Result<Keystore, BasisCryptoError> {
        Self::from_pkcs12_repr(path, password)
            .map_err(|e| CertificateError::FromPkcs12 {
                path: path.to_path_buf(),
                source: e,
            })
            .map_err(BasisCryptoErrorRepr::from)
            .map_err(BasisCryptoError::from)
    }

    fn from_pkcs12_repr(path: &Path, password: &str) -> Result<Keystore, FromPkcs12Error> {
        let bytes = fs::read(path).map_err(|e| FromPkcs12Error::IO {
            path: path.to_path_buf(),
            source: e,
        })?;
        let p12: Pkcs12 = Pkcs12::from_der(&bytes).map_err(|e| FromPkcs12Error::FromDer {
            path: path.to_path_buf(),
            source: e,
        })?;
        p12.parse2(password)
            .map(|p| Keystore {
                pcks12: Some(p),
                path: path.to_path_buf(),
                extension: CertificateExtension::default(),
            })
            .map_err(|e| FromPkcs12Error::Parse2 {
                path: path.to_path_buf(),
                source: e,
            })
    }

    /// Keystore is a directory with the list of files withing the directory
    ///
    /// # Error
    /// if somwthing is going wrong
    pub fn from_directory(path: &Path) -> Result<Keystore, BasisCryptoError> {
        if !path.is_dir() {
            return Err(BasisCryptoError::from(BasisCryptoErrorRepr::from(
                CertificateError::NotDir {
                    path: path.to_path_buf(),
                },
            )));
        }
        Ok(Self {
            pcks12: None,
            path: path.to_path_buf(),
            extension: CertificateExtension::default(),
        })
    }

    /// Check if the keystore is based on p12
    ///
    /// If false, it is based on directory
    pub fn is_pcks12(&self) -> bool {
        self.pcks12.is_some()
    }

    pub fn set_certificate_extension(&mut self, ext: &CertificateExtension) {
        ext.clone_into(&mut self.extension);
    }

    /// Get a given certificate from the keystore
    ///
    /// # Error
    /// if somwthing is going wrong
    pub fn get_public_certificate(
        &self,
        authority: &str,
    ) -> Result<SigningCertificate, BasisCryptoError> {
        match self.is_pcks12() {
            true => self
                .get_certificate_from_pcks12(authority)
                .map_err(CertificateError::from),
            false => self
                .get_certificate_from_dir(authority)
                .map_err(CertificateError::from),
        }
        .map_err(BasisCryptoErrorRepr::from)
        .map_err(BasisCryptoError::from)
    }

    fn get_certificate_from_pcks12(
        &self,
        authority: &str,
    ) -> Result<SigningCertificate, GetPublicCertFromFromPkcs12Error> {
        let pcks12 = self.pcks12.as_ref().unwrap();
        let cas = match pcks12.ca.as_ref() {
            Some(s) => s,
            None => {
                return Err(GetPublicCertFromFromPkcs12Error::MissingCAList {
                    path: self.path.to_path_buf(),
                });
            }
        };
        for x in cas.iter() {
            for e in x.issuer_name().entries() {
                if e.object().to_string() == *"commonName"
                    && e.data().as_slice() == authority.as_bytes()
                {
                    return Ok(SigningCertificate {
                        authority: authority.to_owned(),
                        x509: x.to_owned(),
                        secret_key: None,
                    });
                }
            }
        }
        Err(GetPublicCertFromFromPkcs12Error::MissingCA {
            path: self.path.to_path_buf(),
            name: authority.to_string(),
        })
    }

    fn get_certificate_from_dir(
        &self,
        authority: &str,
    ) -> Result<SigningCertificate, GetPublicCertFromFromDirError> {
        let p = self.path.join(format!("{}{}", authority, self.extension));
        let buf = fs::read(&p).map_err(|e| GetPublicCertFromFromDirError::IO {
            source: e,
            path: p.clone(),
        })?;
        let cert = X509::from_pem(&buf).map_err(|e| GetPublicCertFromFromDirError::FromPem {
            path: p.clone(),
            source: e,
        })?;
        Ok(SigningCertificate {
            authority: authority.to_owned(),
            x509: cert,
            secret_key: None,
        })
    }

    /// Get the secret certificate from the keystore
    ///
    /// # Error
    /// if something is going wrong
    pub fn get_secret_certificate(&self) -> Result<SigningCertificate, BasisCryptoError> {
        self.get_secret_certificate_repr()
            .map_err(CertificateError::from)
            .map_err(BasisCryptoErrorRepr::from)
            .map_err(BasisCryptoError::from)
    }

    fn get_secret_certificate_repr(
        &self,
    ) -> Result<SigningCertificate, GetPrivateCertificateError> {
        if !self.is_pcks12() {
            return Err(GetPrivateCertificateError::OnlyPkc12 {
                fct: "get_secret_certificate",
            });
        }
        let pcks12 = self.pcks12.as_ref().unwrap();
        let sk: &PKey<Private> =
            pcks12
                .pkey
                .as_ref()
                .ok_or(GetPrivateCertificateError::KeyStoreMissingSecretKey {
                    path: self.path.to_path_buf(),
                })?;
        let cert = pcks12.cert.as_ref().ok_or(
            GetPrivateCertificateError::KeyStoreMissingCertSecretKey {
                path: self.path.to_path_buf(),
            },
        )?;
        let mut authority = String::new();
        for e in cert.issuer_name().entries() {
            if e.object().to_string() == *"commonName" {
                authority = e
                    .data()
                    .as_utf8()
                    .map_err(|e| GetPrivateCertificateError::SecretKeyError {
                        path: self.path.to_path_buf(),
                        source: e,
                    })?
                    .to_string();
                break;
            }
        }
        Ok(SigningCertificate {
            authority,
            x509: cert.to_owned(),
            secret_key: Some(Secretkey(sk.to_owned())),
        })
    }
}

impl SigningCertificate {
    /// Get the public key from the certificate
    ///
    /// # Error
    /// if somwthing is going wrong
    pub fn public_key(&self) -> Result<PublicKey, BasisCryptoError> {
        self.x509
            .public_key()
            .map(PublicKey)
            .map_err(|e| SigningCertificateError::CertificateErrorPK {
                authority: self.authority.to_string(),
                source: e,
            })
            .map_err(CertificateError::from)
            .map_err(BasisCryptoErrorRepr::from)
            .map_err(BasisCryptoError::from)
    }

    /// Get the secret key from the certificate
    pub fn secret_key(&self) -> &Option<Secretkey> {
        &self.secret_key
    }

    /// Get the authority of the certificate
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// Check the validity of the date according to now
    ///
    /// # Error
    /// if somwthing is going wrong
    pub fn is_valid_time(&self) -> Result<bool, BasisCryptoError> {
        let not_before = self.x509.not_before();
        let not_after = self.x509.not_after();
        let now = Asn1Time::days_from_now(0)
            .map_err(|e| SigningCertificateError::CertificateErrorTime {
                authority: self.authority.to_string(),
                source: e,
            })
            .map_err(CertificateError::from)
            .map_err(BasisCryptoErrorRepr::from)
            .map_err(BasisCryptoError::from)?;
        Ok(not_before < now && now <= not_after)
    }

    pub fn x509(&self) -> &X509 {
        &self.x509
    }

    /// Return the digest (hash256) fingerprint of the certificate
    ///
    /// # Error
    /// if somwthing is going wrong
    pub fn digest(&self) -> Result<ByteArray, BasisCryptoError> {
        Ok(ByteArray::from(
            &self
                .x509
                .digest(MessageDigest::sha256())
                .map_err(|e| SigningCertificateError::CertificateDigest {
                    authority: self.authority.to_string(),
                    source: e,
                })
                .map_err(CertificateError::from)
                .map_err(BasisCryptoErrorRepr::from)
                .map_err(BasisCryptoError::from)?
                .to_vec(),
        ))
    }
}

impl PublicKey {
    pub(crate) fn pkey_public(&self) -> &PKey<Public> {
        &self.0
    }
}

impl Secretkey {
    pub(crate) fn pkey_private(&self) -> &PKey<Private> {
        &self.0
    }
}

impl Default for CertificateExtension {
    fn default() -> Self {
        Self::Cer
    }
}

impl Display for CertificateExtension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                CertificateExtension::Cer => ".cer".to_string(),
                CertificateExtension::Pem => ".pem".to_string(),
            }
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::byte_array::EncodeTrait;
    use std::path::PathBuf;
    use std::str;

    const PASSWORD_VERIFIER: &str = "OEqNVCv5UB81fEq7OB8wDIGKUYzpnQwZ";
    const PASSWORD_CANTON: &str = "FCtfxF9HTvOnfZaTc2kuB+yGbA0/RAMR";

    fn get_dir() -> PathBuf {
        Path::new("./").join("test_data").join("direct-trust")
    }
    fn get_file() -> PathBuf {
        get_dir().join("public_keys_keystore_verifier.p12")
    }

    fn get_signing_file() -> PathBuf {
        get_dir().join("signing_keystore_canton.p12")
    }

    #[test]
    fn test_read_pem() {
        let p = get_dir().join("canton.cer");
        let buf = fs::read(p).unwrap();
        let _x509 = X509::from_pem(&buf).unwrap();
    }

    #[test]
    fn test_create_pkcs12() {
        let ks = Keystore::from_pkcs12(&get_file(), PASSWORD_VERIFIER);
        assert!(ks.is_ok());
        assert!(ks.unwrap().is_pcks12());
        let ks2 = Keystore::from_pkcs12(&get_signing_file(), PASSWORD_CANTON);
        assert!(ks2.is_ok());
        assert!(ks2.unwrap().is_pcks12());
        let ks_err = Keystore::from_pkcs12(&get_file(), "toto");
        assert!(ks_err.is_err());
        let ks_err2 = Keystore::from_pkcs12(Path::new("./toto.p12"), PASSWORD_VERIFIER);
        assert!(ks_err2.is_err());
    }

    #[test]
    fn test_create_dir() {
        let ks = Keystore::from_directory(&get_dir());
        assert!(ks.is_ok());
        assert!(!ks.unwrap().is_pcks12());
        let ks_err = Keystore::from_pkcs12(&get_file(), "toto");
        assert!(ks_err.is_err());
    }

    #[test]
    fn get_certificate_for_pkcs12() {
        let ks = Keystore::from_pkcs12(&get_file(), PASSWORD_VERIFIER).unwrap();
        let cert = ks.get_public_certificate("canton");
        assert!(cert.is_ok());
        assert_eq!(cert.unwrap().authority(), "canton");
        let cert = ks.get_public_certificate("sdm_config");
        assert!(cert.is_ok());
        let cert = ks.get_public_certificate("sdm_tally");
        assert!(cert.is_ok());
        let cert = ks.get_public_certificate("voting_server");
        assert!(cert.is_ok());
        let cert = ks.get_public_certificate("control_component_1");
        assert!(cert.is_ok());
        let cert = ks.get_public_certificate("control_component_2");
        assert!(cert.is_ok());
        let cert = ks.get_public_certificate("control_component_3");
        assert!(cert.is_ok());
        let cert = ks.get_public_certificate("control_component_4");
        assert!(cert.is_ok());
        let cert = ks.get_public_certificate("toto");
        assert!(cert.is_err());
    }

    #[test]
    fn get_certificate_for_dir() {
        let ks = Keystore::from_directory(&get_dir()).unwrap();
        let cert = ks.get_public_certificate("canton");
        assert!(cert.is_ok());
        assert_eq!(cert.unwrap().authority(), "canton");
        let cert = ks.get_public_certificate("sdm_config");
        assert!(cert.is_ok());
        let cert = ks.get_public_certificate("sdm_tally");
        assert!(cert.is_ok());
        let cert = ks.get_public_certificate("voting_server");
        assert!(cert.is_ok());
        let cert = ks.get_public_certificate("control_component_1");
        assert!(cert.is_ok());
        let cert = ks.get_public_certificate("control_component_2");
        assert!(cert.is_ok());
        let cert = ks.get_public_certificate("control_component_3");
        assert!(cert.is_ok());
        let cert = ks.get_public_certificate("control_component_4");
        assert!(cert.is_ok());
        let cert = ks.get_public_certificate("toto");
        assert!(cert.is_err());
    }

    #[test]
    fn get_secret_certificate() {
        let ks = Keystore::from_pkcs12(&get_file(), PASSWORD_VERIFIER).unwrap();
        let cert = ks.get_secret_certificate();
        assert!(cert.is_err());
        let ks2 = Keystore::from_pkcs12(&get_signing_file(), PASSWORD_CANTON).unwrap();
        let cert2 = ks2.get_secret_certificate();
        assert!(cert2.is_ok());
    }

    #[test]
    fn digest() {
        let ks = Keystore::from_pkcs12(&get_file(), PASSWORD_VERIFIER).unwrap();
        assert_eq!(
            ks.get_public_certificate("canton")
                .unwrap()
                .digest()
                .unwrap()
                .base16_encode()
                .unwrap()
                .to_lowercase(),
            "37dc2ff6d555fee32d0469c365ed47bdd5a5448ef38a9edd0f05e0b055a12162"
        );
    }
}
