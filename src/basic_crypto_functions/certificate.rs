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

/// Wrapper to the keystore give in a file
pub struct Keystore {
    pcks12: ParsedPkcs12_2,
    path: PathBuf,
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
    pub fn read_keystore(path: &Path, password: &str) -> Result<Keystore, BasisCryptoError> {
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
                pcks12: p,
                path: path.to_path_buf(),
            })
            .map_err(|e| BasisCryptoError::Keystore {
                msg: format!("Error parsing keystore file {:?}", path),
                source: e,
            })
    }

    /// Get a given certificate from the keystore
    ///
    /// # Error
    /// if somwthing is going wrong
    pub fn get_certificate(&self, authority: &str) -> Result<SigningCertificate, BasisCryptoError> {
        let cas = match self.pcks12.ca.as_ref() {
            Some(s) => s,
            None => {
                return Err(BasisCryptoError::KeyStoreMissingCAList(
                    self.path.to_path_buf(),
                ));
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
                    });
                }
            }
        }
        Err(BasisCryptoError::KeyStoreMissingCA {
            path: self.path.to_path_buf(),
            name: authority.to_string(),
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::byte_array::Encode;
    use std::path::PathBuf;
    use std::str;

    const PASSWORD: &str = "testPassword";

    fn get_file() -> PathBuf {
        Path::new("./")
            .join("test_data")
            .join("direct-trust")
            .join("public_keys_keystore_verifier.p12")
    }

    #[test]
    fn test_create() {
        let ks = Keystore::read_keystore(&get_file(), PASSWORD);
        assert!(ks.is_ok());
        let ks_err = Keystore::read_keystore(&get_file(), "toto");
        assert!(ks_err.is_err());
        let ks_err2 = Keystore::read_keystore(Path::new("./toto.p12"), PASSWORD);
        assert!(ks_err2.is_err());
    }

    #[test]
    fn get_certificate() {
        let ks = Keystore::read_keystore(&get_file(), PASSWORD).unwrap();
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
        let ks = Keystore::read_keystore(&get_file(), PASSWORD).unwrap();
        assert_eq!(
            ks.get_certificate("canton")
                .unwrap()
                .digest()
                .unwrap()
                .base16_encode(),
            "51fcea9139ce3de992eeee1ef77d1e6461e747dff3e3fa52d23f855a319cc35e".to_uppercase()
        );
    }
}
