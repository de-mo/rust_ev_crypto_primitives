// Copyright © 2023 Denis Morel
//
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
//! [Crypo-primitives](https://gitlab.com/swisspost-evoting/crypto-primitives/crypto-primitives), version 1.4.1
//!
//! The crate reduces actually at the necessary functions for the Verifier. The crate is grouped in modules releated
//! to themes, like the specifications
//!
//! The module `crate::basic_crypto_functions` contains a wrapper to openssl. Details about installation and functionalities
//! can be found on the crate [openssl].
//!
//! The crate ist based on [rug] that is strongly performant, but GMP must be installed for compilation.
//! See the requirements and installation path in the crate documentation [rug](https://crates.io/crates/rug)
//!
//! If a method should return an error, then each error type is specified per module and is transparent
//! to the user of the crate.
//!
//! # Features
//!
//! Following feature is possible:
//! - "checks": The library will perform checks of the input data, according to the specifications of Swiss Post.
//!   This reduces the performance. If the checks are performed during the usage of the crate, it is recommended,
//!   not to activate the feature
//!

pub mod alphabets;
pub mod argon2;
pub mod basic_crypto_functions;
mod byte_array;
pub mod direct_trust;
pub mod elgamal;
mod hashing;
mod integer;
pub mod mix_net;
mod number_theory;
pub mod random;
mod shared_error;
pub mod signature;
pub mod string;
pub mod zero_knowledge_proofs;

pub use byte_array::{ByteArray, ByteArrayError, DecodeTrait, EncodeTrait};
pub use hashing::{HashError, HashableMessage, RecursiveHashTrait};
pub use integer::{
    prepare_fixed_based_optimization, ToByteArryTrait, ConstantsTrait, Hexa, IntegerOperationError,
    ModExponentiateError, OperationsTrait,
};
pub use number_theory::{
    IsPrimeTrait, JacobiError, JacobiTrait, NotPrimeError, QuadraticResidueTrait, SmallPrimeError,
    SmallPrimeTrait,
};
pub use rug::Integer;
pub use shared_error::{NotOddError, NotPositiveError};

/// The length of the group parameter `p` according to the security level in the specifications
pub const GROUP_PARAMETER_P_LENGTH: usize = 3072;

/// The length of the group parameter `q` according to the security level in the specifications
pub const GROUP_PARAMETER_Q_LENGTH: usize = 3071;

/// The security length according to the security level in the specifications
pub const SECURITY_STRENGTH: usize = 128;

type DomainVerificationFunctionBoxed<T, E> = Box<dyn Fn(&T) -> Vec<E>>;

/// Structure containing the verifications for the generic object T with the error type E
pub struct DomainVerifications<T: Sized, E> {
    verification_fns: Vec<DomainVerificationFunctionBoxed<T, E>>,
}

/// Trait for the verification of a the domain of a strucut
///
/// All pseudocode algorithms define the domain for each input. The trait implements
/// the verification of the domain for a data structure
///
/// In the default implementation, nothing will be verified
///
/// It is possible to implement the function `verifiy_domain` or the function `new_domain_verifications`
pub trait VerifyDomainTrait<E>: Sized {
    /// Create the new list of verications containing all the necessary verifications
    /// for the object implementing the trait
    fn new_domain_verifications() -> DomainVerifications<Self, E> {
        DomainVerifications::default()
    }

    /// Verify the domain
    ///
    /// Return a vector of `E`. Empty if no error found
    fn verifiy_domain(&self) -> Vec<E> {
        let verifications = Self::new_domain_verifications();
        verifications.iter().flat_map(|f| f(self)).collect()
    }
}

impl<T, E> Default for DomainVerifications<T, E> {
    fn default() -> Self {
        Self {
            verification_fns: Default::default(),
        }
    }
}

impl<T, E> DomainVerifications<T, E> {
    /// Add Verification function to the structure
    pub fn add_verification(&mut self, fct: impl (Fn(&T) -> Vec<E>) + 'static) {
        self.verification_fns.push(Box::new(fct));
    }

    /// Add a verification return a vector of vector of errors
    pub fn add_verification_with_vec_of_vec_errors(
        &mut self,
        fct: impl (Fn(&T) -> Vec<Vec<E>>) + 'static,
    ) {
        self.add_verification(move |t| {
            let mut res = vec![];
            for r in fct(t) {
                for e in r {
                    res.push(e);
                }
            }
            res
        })
    }

    /// Iterate over ale the functions
    pub fn iter(&self) -> std::slice::Iter<'_, DomainVerificationFunctionBoxed<T, E>> {
        self.verification_fns.iter()
    }
}

#[cfg(test)]
mod test_json_data {
    use crate::{Hexa, Integer};
    use serde_json::Value;

    pub fn json_array_value_to_array_string(array: &Value) -> Vec<String> {
        array
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect()
    }

    pub fn json_array_value_to_array_mpinteger(array: &Value) -> Vec<Integer> {
        Integer::from_hexa_string_slice(&json_array_value_to_array_string(array)).unwrap()
    }

    pub fn json_value_to_mpinteger(value: &Value) -> Integer {
        Integer::from_hexa_string(value.as_str().unwrap()).unwrap()
    }
}
