//! Crate implementing the cryptographic functions for E-Voting
//!
//! The crate reduces actually at the necessary functions for the Verifier. The crate is grouped in modules releated to themes.
//!
//! The module [openssl_wrapper] contains a wrapper to openssl. Details about installation and functionalities can be found
//! on the crate [openssl].
//!
//! If a method should return an error, then each error type is specified per module and is transparent to the user of the crate.
//!
//! Features:
//! - "checks": The library will perform checks of the input data, according to the specifications of Swiss Post. This reduces the
//! performance. If the checks are performed during the usage of the crate, it is recommended, not to activate the feature
//!

mod byte_array;
mod direct_trust;
mod elgamal;
mod hashing;
mod num_bigint;
mod number_theory;
mod openssl_wrapper;
mod signature;
mod zero_knowledge_proof;

pub use byte_array::{ByteArray, Decode, Encode};
pub use direct_trust::{
    CertificateAuthority, DirectTrust, DirectTrustCertificate, DirectTrustError,
};
pub use elgamal::{ElgamalError, EncryptionParameters, get_small_prime_group_members};
pub use hashing::{HashError, HashTrait, HashableMessage};
pub use num_bigint::{BigUIntError, ByteLength, Constants, Hexa, Operations};
pub use number_theory::is_small_prime;
pub use signature::{SignatureError, VerifiySignatureTrait};
pub use zero_knowledge_proof::{verify_exponentiation, verify_schnorr, ZeroKnowledgeProofError};

pub const GROUP_PARAMETER_P_LENGTH: usize = 3072;
