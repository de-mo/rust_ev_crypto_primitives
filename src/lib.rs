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

pub mod byte_array;
pub mod direct_trust;
pub mod elgamal;
pub mod hashing;
pub mod num_bigint;
pub mod number_theory;
pub mod openssl_wrapper;
pub mod signature;
pub mod zero_knowledge_proof;

pub const GROUP_PARAMETER_P_LENGTH: usize = 3072;

