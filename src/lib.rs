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

//! Crate implementing the cryptographic functions for E-Voting
//!
//! It is based on the specifications of Swiss Post, according to the following document version:
//! [Crypo-primitives](https://gitlab.com/swisspost-evoting/crypto-primitives/crypto-primitives), version 1.4.0
//!
//! The crate reduces actually at the necessary functions for the Verifier. The crate is grouped in modules releated
//! to themes, like the specifications
//!
//! The module `crate::openssl_wrapper` contains a wrapper to openssl. Details about installation and functionalities
//! can be found on the crate [openssl].
//!
//! If a method should return an error, then each error type is specified per module and is transparent
//! to the user of the crate.
//!
//! # Features
//!
//! Following features are possible:
//! - "rug": Use `Integer` of crate [sug](https://crates.io/crates/rug) for mulitple precision numbers
//! - "num-bigint": Use the `BigUint`of crate [num-bigint](https://crates.io/crates/num-bigint) for mulitple precision
//! numbers
//! - "checks": The library will perform checks of the input data, according to the specifications of Swiss Post.
//! This reduces the performance. If the checks are performed during the usage of the crate, it is recommended,
//! not to activate the feature
//!
//! The feature "rug" is strongly more performant, but GMP must be installed for compilation.
//! See the requirements and installation path in the crate documentation [rug](https://crates.io/crates/rug)

mod basic_crypto_functions;
pub mod byte_array;
pub mod direct_trust;
pub mod elgamal;
pub mod hashing;
pub mod integer;
pub mod number_theory;
pub mod signature;
pub mod zero_knowledge_proof;

pub use basic_crypto_functions::CertificateExtension;
pub use byte_array::{ByteArray, Decode, Encode};
pub use direct_trust::{DirectTrustCertificate, DirectTrustError, Keystore};
pub use elgamal::{
    check_g, check_p, check_q, get_small_prime_group_members, ElgamalError, EncryptionParameters,
};
pub use hashing::{HashError, HashableMessage, RecursiveHashTrait};
pub use integer::{ByteLength, Constants, Hexa, MPIntegerError, Operations};
pub use number_theory::SmallPrimeTrait;
pub use signature::{verify_signature, SignatureError};
pub use zero_knowledge_proof::{verify_exponentiation, verify_schnorr, ZeroKnowledgeProofError};

/// The length of the group parameter `p` according to the security level in the specifications
pub const GROUP_PARAMETER_P_LENGTH: usize = 3072;

/// The security length according to the security level in the specifications
pub const SECURITY_LENGTH: usize = 128;
