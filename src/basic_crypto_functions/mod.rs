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

//! Module to wrap the openssl library for crypto functions

mod argon2;
mod certificate;
mod hash;
mod rand;
mod signature;

pub use argon2::*;
pub use certificate::*;
pub use hash::*;
pub use rand::*;
pub use signature::*;

use openssl::error::ErrorStack;
use std::{io, path::PathBuf};
use thiserror::Error;

// Enum with the type of error generated by openSSL_wrapper
#[derive(Error, Debug)]
pub enum BasisCryptoError {
    #[error("Path is not a directory {path}")]
    Dir { path: String },
    #[error("IO error caused by {source}: {msg}")]
    IO { msg: String, source: io::Error },
    #[error("Keystore error {msg} caused by {source}")]
    Keystore { msg: String, source: ErrorStack },
    #[error("Keystore {0} has no list of CA")]
    KeyStoreMissingCAList(PathBuf),
    #[error("The ca with name {name} is not present in the Keystore {path}")]
    KeyStoreMissingCA { path: PathBuf, name: String },
    #[error("Error reading public key in the certificate {name} caused by {source}")]
    CertificateErrorPK { name: String, source: ErrorStack },
    #[error("Error of time during time check of the certificate {name} caused by {source}")]
    CertificateErrorTime { name: String, source: ErrorStack },
    #[error("Digest (Fingerprint) error caused by {source}: {msg}")]
    CertificateDigest { msg: String, source: ErrorStack },
    #[error("PublicKey error caused by {source}: {msg}")]
    PublicKeyError { msg: String, source: ErrorStack },
    #[error("{msg} caused by {source}")]
    SignatureVerify { msg: String, source: ErrorStack },
    #[error("Hash error caused by {source}: {msg}")]
    HashError { msg: String, source: ErrorStack },
    #[error("Argon2 error caused by {argon2_error_source}: {msg}")]
    Argon2Error {
        msg: String,
        argon2_error_source: Argon2Error,
    },
    #[error("Random error caused by {source}: {msg}")]
    RandomError { msg: String, source: ErrorStack },
}
