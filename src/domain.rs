// Copyright © 2023 Denis Morel
//
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

//! Module to implement the verification of the domain of a data with context

/// Type definition for a function that verifies the domain of T with context C
/// returning a vector of errors of type E
pub type DomainVerificationFunctionBoxed<C, T, E> = Box<dyn Fn(&T, &C) -> Vec<E>>;

#[derive(Debug, Default)]
/// Empty context structure when no context is necessary
pub struct EmptyContext;

/// Structure containing the verifications for the generic object T with the error type E
pub struct DomainVerifications<C: Sized, T: Sized, E> {
    verification_fns: Vec<DomainVerificationFunctionBoxed<C, T, E>>,
}

/// Trait for the verification of a the domain of a strucut
///
/// All pseudocode algorithms define the domain for each input. The trait implements
/// the verification of the domain for a data structure
///
/// In the default implementation, nothing will be verified
///
/// If no context is necessary, the structure `EmptyContext` can be used
/// ```ignore
/// use rust_ev_crypto_primitives::domain::{VerifyDomainTrait, EmptyContext};
/// struct MyStruct {
///    value: u32,
/// }
/// impl VerifyDomainTrait<EmptyContext, String> for MyStruct {};
/// ```
pub trait VerifyDomainTrait<C: Sized, E>: Sized {
    /// Create the new list of verications containing all the necessary verifications
    /// for the object implementing the trait
    fn new_domain_verifications() -> DomainVerifications<C, Self, E> {
        DomainVerifications::default()
    }

    /// Verify the domain
    ///
    /// Return a vector of `E`. Empty if no error found
    fn verifiy_domain(&self, context: &C) -> Vec<E> {
        let verifications = Self::new_domain_verifications();
        verifications
            .iter()
            .flat_map(|f| f(self, context))
            .collect()
    }
}

impl<C, T, E> Default for DomainVerifications<C, T, E> {
    /// Default implementation creating an empty list of verifications
    fn default() -> Self {
        Self {
            verification_fns: Default::default(),
        }
    }
}

impl<C, T, E> DomainVerifications<C, T, E> {
    /// Add Verification function to the structure
    pub fn add_verification(&mut self, fct: impl (Fn(&T, &C) -> Vec<E>) + 'static) {
        self.verification_fns.push(Box::new(fct));
    }

    /// Add a verification returning a vector of vector of errors
    pub fn add_verification_with_vec_of_vec_errors(
        &mut self,
        fct: impl (Fn(&T, &C) -> Vec<Vec<E>>) + 'static,
    ) {
        self.add_verification(move |t, c| fct(t, c).into_iter().flatten().collect())
    }

    /// Iterate over all the functions
    pub fn iter(&self) -> std::slice::Iter<'_, DomainVerificationFunctionBoxed<C, T, E>> {
        self.verification_fns.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MyStruct {
        value: u32,
    }

    impl VerifyDomainTrait<EmptyContext, String> for MyStruct {
        fn new_domain_verifications() -> DomainVerifications<EmptyContext, Self, String> {
            let mut verifications = DomainVerifications::default();

            verifications.add_verification(|s: &MyStruct, _c: &EmptyContext| {
                let mut errors = Vec::new();
                if s.value < 10 {
                    errors.push("Value is less than 10".to_string());
                }
                if s.value > 100 {
                    errors.push("Value is greater than 100".to_string());
                }
                errors
            });

            verifications
        }
    }

    #[test]
    fn test_domain_verification() {
        let my_struct = MyStruct { value: 5 };
        let errors = my_struct.verifiy_domain(&EmptyContext);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0], "Value is less than 10");

        let my_struct = MyStruct { value: 150 };
        let errors = my_struct.verifiy_domain(&EmptyContext);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0], "Value is greater than 100");

        let my_struct = MyStruct { value: 50 };
        let errors = my_struct.verifiy_domain(&EmptyContext);
        assert!(errors.is_empty());
    }

    #[test]
    fn test_domain_verification_no_errors() {
        let my_struct = MyStruct { value: 50 };
        let errors = my_struct.verifiy_domain(&EmptyContext);
        assert!(errors.is_empty());
    }

    struct MyStructNextedErrors;

    impl VerifyDomainTrait<EmptyContext, String> for MyStructNextedErrors {
        fn new_domain_verifications() -> DomainVerifications<EmptyContext, Self, String> {
            let mut verifications = DomainVerifications::default();

            verifications.add_verification_with_vec_of_vec_errors(
                |_s: &MyStructNextedErrors, _c: &EmptyContext| {
                    vec![vec!["error1".to_string(), "error2".to_string()]]
                },
            );

            verifications
        }
    }

    #[test]
    fn test_domain_verification_nexted_errors() {
        let my_struct = MyStructNextedErrors {};
        let errors = my_struct.verifiy_domain(&EmptyContext);
        assert_eq!(errors, vec!["error1".to_string(), "error2".to_string()]);
    }
}
