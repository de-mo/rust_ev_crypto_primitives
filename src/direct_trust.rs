//! Module implementing the direct trust

use thiserror::Error;

use super::basic_crypto_functions::{
    BasisCryptoError, {Keystore as SslKeystore, SigningCertificate},
};
use std::{fs, io, path::Path};

/// Struct representing a direct trust
pub struct Keystore {
    keystore: SslKeystore,
}

impl Keystore {
    /// Create a new direct trust certificate reading the store at location for
    /// the given authority
    pub fn new(keystore_path: &Path, password_file_path: &Path) -> Result<Self, DirectTrustError> {
        let pwd = fs::read_to_string(password_file_path).map_err(|e| DirectTrustError::IO {
            msg: format!(
                "Error reading password file {}",
                &password_file_path.display()
            ),
            source: e,
        })?;
        Ok(Keystore {
            keystore: SslKeystore::read_keystore(keystore_path, &pwd)
                .map_err(DirectTrustError::Keystore)?,
        })
    }

    pub fn certificate(&self, authority: &str) -> Result<DirectTrustCertificate, DirectTrustError> {
        let cert = self
            .keystore
            .get_certificate(&String::from(authority))
            .map_err(DirectTrustError::Certificate)?;
        Ok(DirectTrustCertificate {
            authority: authority.to_string(),
            cert,
        })
    }
}

/// Struct representing a direct trust certificate
#[derive(Clone)]
pub struct DirectTrustCertificate {
    authority: String,
    cert: SigningCertificate,
}

impl DirectTrustCertificate {
    /// Get authority of the certificate
    pub fn authority(&self) -> &String {
        &self.authority
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

    const KEYSTORE_FILE_NAME: &str = "public_keys_keystore_verifier.p12";
    const PASSWORD_FILE_NAME: &str = "public_keys_keystore_verifier_pw.txt";

    fn get_location() -> PathBuf {
        Path::new("./").join("test_data").join("direct-trust")
    }

    #[test]
    fn test_create() {
        let dt = Keystore::new(
            &get_location().join(Path::new(KEYSTORE_FILE_NAME)),
            &get_location().join(Path::new(PASSWORD_FILE_NAME)),
        )
        .unwrap();
        //let dt = DirectTrustCertificate::new(, &CertificateAuthority::Canton);
        assert!(dt.certificate("canton").is_ok());
        assert!(dt.certificate("toto").is_err());
        let dt_err = Keystore::new(
            Path::new("./toto"),
            &get_location().join(Path::new(PASSWORD_FILE_NAME)),
        );
        assert!(dt_err.is_err());
    }
}
