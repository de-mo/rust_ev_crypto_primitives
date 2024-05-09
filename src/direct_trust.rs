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

//! Module implementing the direct trust

use super::basic_crypto_functions::{
    BasisCryptoError, CertificateExtension, Keystore as SslKeystore, SigningCertificate,
};
use std::{fs, io, path::Path};
use thiserror::Error;

/// Struct representing a direct trust
pub struct Keystore {
    keystore: SslKeystore,
}

impl Keystore {
    /// Read a direct trust keystore from pkcs12
    pub fn from_pkcs12(
        keystore_path: &Path,
        password_file_path: &Path,
    ) -> Result<Self, DirectTrustError> {
        let pwd = fs::read_to_string(password_file_path).map_err(|e| DirectTrustError::IO {
            msg: format!(
                "Error reading password file {}",
                &password_file_path.display()
            ),
            source: e,
        })?;
        Ok(Keystore {
            keystore: SslKeystore::from_pkcs12(keystore_path, &pwd)
                .map_err(DirectTrustError::Keystore)?,
        })
    }

    /// Read a direct trust keystore from a directory, where the public key certificates are stored
    pub fn from_directory(
        keystore_path: &Path,
        extension: &CertificateExtension,
    ) -> Result<Self, DirectTrustError> {
        let mut ks =
            SslKeystore::from_directory(keystore_path).map_err(DirectTrustError::Keystore)?;
        ks.set_certificate_extension(extension);
        Ok(Self { keystore: ks })
    }

    /// Read the public certificate with the authority given as parameter
    pub fn public_certificate(
        &self,
        authority: &str,
    ) -> Result<DirectTrustCertificate, DirectTrustError> {
        let cert = self
            .keystore
            .get_public_certificate(&String::from(authority))
            .map_err(DirectTrustError::Certificate)?;
        Ok(DirectTrustCertificate { cert })
    }

    /// Read the secret key and associated certificate
    ///
    /// Return an error if no secret key found in the keystore
    pub fn secret_key_certificate(&self) -> Result<DirectTrustCertificate, DirectTrustError> {
        let cert = self
            .keystore
            .get_secret_certificate()
            .map_err(DirectTrustError::Certificate)?;
        Ok(DirectTrustCertificate { cert })
    }
}

/// Struct representing a direct trust certificate
#[derive(Clone)]
pub struct DirectTrustCertificate {
    cert: SigningCertificate,
}

impl DirectTrustCertificate {
    /// Get authority of the certificate
    pub fn authority(&self) -> &str {
        self.cert.authority()
    }

    /// Get the certificate of the authority
    pub fn signing_certificate(&self) -> &SigningCertificate {
        &self.cert
    }
}

// Enum representing the direct trust errors
#[derive(Error, Debug)]
pub enum DirectTrustError {
    #[error("IO error caused by {source}: {msg}")]
    IO { msg: String, source: io::Error },
    #[error(transparent)]
    Keystore(BasisCryptoError),
    #[error(transparent)]
    Certificate(BasisCryptoError),
}

#[cfg(test)]
mod test {
    use super::*;
    use std::path::PathBuf;

    const VERIFIER_KEYSTORE_FILE_NAME: &str = "public_keys_keystore_verifier.p12";
    const VERIFIER_PASSWORD_FILE_NAME: &str = "public_keys_keystore_verifier_pw.txt";
    const CANTON_KEYSTORE_FILE_NAME: &str = "signing_keystore_canton.p12";
    const CANTON_PASSWORD_FILE_NAME: &str = "signing_pw_canton.txt";

    fn get_location() -> PathBuf {
        Path::new("./").join("test_data").join("direct-trust")
    }

    #[test]
    fn test_create_pkcs12() {
        let dt = Keystore::from_pkcs12(
            &get_location().join(Path::new(VERIFIER_KEYSTORE_FILE_NAME)),
            &get_location().join(Path::new(VERIFIER_PASSWORD_FILE_NAME)),
        )
        .unwrap();
        assert!(dt.public_certificate("canton").is_ok());
        assert!(dt.public_certificate("toto").is_err());
        assert!(dt.secret_key_certificate().is_err());
        let dt = Keystore::from_pkcs12(
            &get_location().join(Path::new(CANTON_KEYSTORE_FILE_NAME)),
            &get_location().join(Path::new(CANTON_PASSWORD_FILE_NAME)),
        )
        .unwrap();
        assert!(dt.secret_key_certificate().is_ok());
        let dt_err = Keystore::from_pkcs12(
            Path::new("./toto"),
            &get_location().join(Path::new(VERIFIER_PASSWORD_FILE_NAME)),
        );
        assert!(dt_err.is_err());
    }

    #[test]
    fn test_create_dir() {
        let dt =
            Keystore::from_directory(&get_location(), &CertificateExtension::default()).unwrap();
        //let dt = DirectTrustCertificate::new(, &CertificateAuthority::Canton);
        assert!(dt.public_certificate("canton").is_ok());
        assert!(dt.public_certificate("toto").is_err());
        let dt_err =
            Keystore::from_directory(Path::new("./toto"), &CertificateExtension::default());
        assert!(dt_err.is_err());
    }
}
