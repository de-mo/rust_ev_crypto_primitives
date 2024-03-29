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

//! Wrapper for Certificate functions

use super::BasisCryptoError;
use crate::byte_array::ByteArray;
use openssl::{
    asn1::Asn1Time,
    hash::MessageDigest,
    pkcs12::{ParsedPkcs12_2, Pkcs12},
    pkey::{PKey, Public},
    x509::X509,
};
use std::{
    fs,
    path::{Path, PathBuf},
};

/// Keystore to collect the public keys
///
/// The keystore can be a p12 file or a directory containing the certificates
/// - In the first case, the CN of the certificates must contain the name of the authority
/// - In the second case, the certificates must contain the valid structure, the file name represent the authority
/// and the file extension is given bei [CertificateExtension] (`.cer`, or `.pem`).
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
}

// The struct contaiing the PublicKey
pub struct PublicKey(PKey<Public>);

impl Keystore {
    /// Read the keystore from file with password to open it
    ///
    /// # Error
    /// if somwthing is going wrong
    pub fn from_pkcs12(path: &Path, password: &str) -> Result<Keystore, BasisCryptoError> {
        let bytes = fs::read(path).map_err(|e| BasisCryptoError::IO {
            msg: format!("Error reading keystore file {:?}", path),
            source: e,
        })?;
        let p12: Pkcs12 = Pkcs12::from_der(&bytes).map_err(|e| BasisCryptoError::Keystore {
            msg: format!("Error reading keystore file {:?}", path),
            source: e,
        })?;
        p12.parse2(password)
            .map(|p| Keystore {
                pcks12: Some(p),
                path: path.to_path_buf(),
                extension: CertificateExtension::default(),
            })
            .map_err(|e| BasisCryptoError::Keystore {
                msg: format!("Error parsing keystore file {:?}", path),
                source: e,
            })
    }

    /// Keystore is a directory with the list of files withing the directory
    ///
    /// # Error
    /// if somwthing is going wrong
    pub fn from_directory(path: &Path) -> Result<Keystore, BasisCryptoError> {
        if !path.is_dir() {
            return Err(BasisCryptoError::Dir {
                path: path.to_str().unwrap().to_string(),
            });
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
        self.extension = ext.to_owned();
    }

    /// Get a given certificate from the keystore
    ///
    /// # Error
    /// if somwthing is going wrong
    pub fn get_certificate(&self, authority: &str) -> Result<SigningCertificate, BasisCryptoError> {
        match self.is_pcks12() {
            true => self.get_certificate_from_pcks12(authority),
            false => self.get_certificate_from_dir(authority),
        }
    }

    fn get_certificate_from_pcks12(
        &self,
        authority: &str,
    ) -> Result<SigningCertificate, BasisCryptoError> {
        let pcks12 = self.pcks12.as_ref().unwrap();
        let cas = match pcks12.ca.as_ref() {
            Some(s) => s,
            None => {
                return Err(BasisCryptoError::KeyStoreMissingCAList(
                    self.path.to_path_buf(),
                ));
            }
        };
        // println!("length: {:?}", cas.len());
        for x in cas.iter() {
            // println!("subject_name: {:?}", x.subject_name());
            // println!("issuer_name: {:?}", x.issuer_name());
            for e in x.issuer_name().entries() {
                if e.object().to_string() == *"commonName"
                    && e.data().as_slice() == authority.as_bytes()
                {
                    return Ok(SigningCertificate {
                        authority: authority.to_owned(),
                        x509: x.to_owned(),
                    });
                }
            }
        }
        Err(BasisCryptoError::KeyStoreMissingCA {
            path: self.path.to_path_buf(),
            name: authority.to_string(),
        })
    }

    fn get_certificate_from_dir(
        &self,
        authority: &str,
    ) -> Result<SigningCertificate, BasisCryptoError> {
        let p = self
            .path
            .join(format!("{}{}", authority, self.extension.to_string()));
        let buf = fs::read(&p).map_err(|e| BasisCryptoError::IO {
            msg: format!("Error reading file {}", p.as_os_str().to_str().unwrap()),
            source: e,
        })?;
        let cert = X509::from_pem(&buf).map_err(|e| BasisCryptoError::CertificateErrorPK {
            name: authority.to_string(),
            source: e,
        })?;
        Ok(SigningCertificate {
            authority: authority.to_owned(),
            x509: cert,
        })
    }
}

impl SigningCertificate {
    /// Get the public key from the certificate
    ///
    /// # Error
    /// if somwthing is going wrong
    pub fn get_public_key(&self) -> Result<PublicKey, BasisCryptoError> {
        self.x509
            .public_key()
            .map(PublicKey)
            .map_err(|e| BasisCryptoError::CertificateErrorPK {
                name: self.authority.to_string(),
                source: e,
            })
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
        let now =
            Asn1Time::days_from_now(0).map_err(|e| BasisCryptoError::CertificateErrorTime {
                name: self.authority.to_string(),
                source: e,
            })?;
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
                .map_err(|e| BasisCryptoError::CertificateDigest {
                    msg: "Error by digest".to_string(),
                    source: e,
                })?
                .to_vec(),
        ))
    }
}

impl PublicKey {
    pub(crate) fn pkey_public(&self) -> &PKey<Public> {
        &self.0
    }
}

impl Default for CertificateExtension {
    fn default() -> Self {
        Self::Cer
    }
}

impl ToString for CertificateExtension {
    fn to_string(&self) -> String {
        match self {
            CertificateExtension::Cer => ".cer".to_string(),
            CertificateExtension::Pem => ".pem".to_string(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::byte_array::Encode;
    use std::path::PathBuf;
    use std::str;

    const PASSWORD: &str = "OEqNVCv5UB81fEq7OB8wDIGKUYzpnQwZ";

    fn get_dir() -> PathBuf {
        Path::new("./").join("test_data").join("direct-trust")
    }
    fn get_file() -> PathBuf {
        get_dir().join("public_keys_keystore_verifier.p12")
    }

    #[test]
    fn test_read_pem() {
        let p = get_dir().join("canton.cer");
        let buf = fs::read(p).unwrap();
        let _x509 = X509::from_pem(&buf).unwrap();
    }

    #[test]
    fn test_create_pkcs12() {
        let ks = Keystore::from_pkcs12(&get_file(), PASSWORD);
        assert!(ks.is_ok());
        assert!(ks.unwrap().is_pcks12());
        let ks_err = Keystore::from_pkcs12(&get_file(), "toto");
        assert!(ks_err.is_err());
        let ks_err2 = Keystore::from_pkcs12(Path::new("./toto.p12"), PASSWORD);
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
        let ks = Keystore::from_pkcs12(&get_file(), PASSWORD).unwrap();
        let cert = ks.get_certificate("canton");
        assert!(cert.is_ok());
        assert_eq!(cert.unwrap().authority(), "canton");
        let cert = ks.get_certificate("sdm_config");
        assert!(cert.is_ok());
        let cert = ks.get_certificate("sdm_tally");
        assert!(cert.is_ok());
        let cert = ks.get_certificate("voting_server");
        assert!(cert.is_ok());
        let cert = ks.get_certificate("control_component_1");
        assert!(cert.is_ok());
        let cert = ks.get_certificate("control_component_2");
        assert!(cert.is_ok());
        let cert = ks.get_certificate("control_component_3");
        assert!(cert.is_ok());
        let cert = ks.get_certificate("control_component_4");
        assert!(cert.is_ok());
        let cert = ks.get_certificate("toto");
        assert!(cert.is_err());
    }

    #[test]
    fn get_certificate_for_dir() {
        let ks = Keystore::from_directory(&get_dir()).unwrap();
        let cert = ks.get_certificate("canton");
        assert!(cert.is_ok());
        assert_eq!(cert.unwrap().authority(), "canton");
        let cert = ks.get_certificate("sdm_config");
        assert!(cert.is_ok());
        let cert = ks.get_certificate("sdm_tally");
        assert!(cert.is_ok());
        let cert = ks.get_certificate("voting_server");
        assert!(cert.is_ok());
        let cert = ks.get_certificate("control_component_1");
        assert!(cert.is_ok());
        let cert = ks.get_certificate("control_component_2");
        assert!(cert.is_ok());
        let cert = ks.get_certificate("control_component_3");
        assert!(cert.is_ok());
        let cert = ks.get_certificate("control_component_4");
        assert!(cert.is_ok());
        let cert = ks.get_certificate("toto");
        assert!(cert.is_err());
    }

    #[test]
    fn digest() {
        let ks = Keystore::from_directory(&get_dir()).unwrap();
        assert_eq!(
            ks.get_certificate("canton")
                .unwrap()
                .digest()
                .unwrap()
                .base16_encode(),
            "2B89BC7645ACE34DB5BFFBAB41727987236050F9CB5AD66BA1ED0A806EE8BC8C".to_uppercase()
        );
    }
}
