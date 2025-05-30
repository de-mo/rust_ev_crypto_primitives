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
// <https://www.gnu.org/licenses/>

use super::{
    arguments::{
        verify_shuffle_argument, ArgumentContext, ShuffleArgument, ShuffleArgumentError,
        ShuffleArgumentVerifyInput, ShuffleStatement, VerifyShuffleArgumentResult,
    },
    commitments::{CommitmentError, CommitmentKey},
    matrix::Matrix,
    MixNetResultTrait, MixnetError, MixnetErrorRepr,
};
use crate::{
    elgamal::{Ciphertext, EncryptionParameters},
    ConstantsTrait, Integer,
};
use std::fmt::Display;
use thiserror::Error;

#[derive(Error, Debug)]
pub(super) enum ShuffleError {
    #[error("The length of C' is not the same than the expected length of C")]
    DifferentCyphertextPrimeLen,
    #[error(
        "In the cypthertexts {name} at position {i}, the size of phis {phis_len} is not the same than the expected size {expected_size}"
    )]
    NotSameLInCyphertexts {
        name: &'static str,
        i: usize,
        phis_len: usize,
        expected_size: usize,
    },
    #[error("Wrong size of N={0}. Must be greater or equal that 2 and less or equal than q")]
    WrongCyphertextPrimeLen(usize),
    #[error("l={0} must be smaller or equal to k={1}")]
    LSmallerOrEqualK(usize, usize),
    #[error("l must be positive")]
    LPositive(usize),
    #[error("Error creating commitment key")]
    VerifiableCommitmentKeyError(#[from] CommitmentError),
    #[error("Error creating shuffle statment")]
    ShuffleStatement { source: Box<ShuffleArgumentError> },
    #[error("Error creating inputs for shuffle argument")]
    ShuffleArgumentInput { source: Box<ShuffleArgumentError> },
    #[error("Error verifying shuffle argument")]
    VerifyShuffleArgument { source: Box<ShuffleArgumentError> },
}

/// The result of the verification of the shuffle
#[derive(Debug)]
pub struct VerifyShuffleResult {
    pub verify_shuffle_argument_result: VerifyShuffleArgumentResult,
}

/// Verify Shuffle according to the specification of Swiss Post (algorithm 9.2)
///
/// # return
/// A stucture containing the result of the verification
/// An error is something goes wrong
pub fn verify_shuffle(
    ep: &EncryptionParameters,
    upper_cs: &[Ciphertext],
    upper_c_primes: &[Ciphertext],
    shuffle_argument: &ShuffleArgument,
    pks: &[Integer],
) -> Result<VerifyShuffleResult, MixnetError> {
    verify_shuffle_impl(ep, upper_cs, upper_c_primes, shuffle_argument, pks)
        .map_err(MixnetErrorRepr::from)
        .map_err(|e| MixnetError {
            source: Box::new(e),
        })
}

fn verify_shuffle_impl(
    ep: &EncryptionParameters,
    upper_cs: &[Ciphertext],
    upper_c_primes: &[Ciphertext],
    shuffle_argument: &ShuffleArgument,
    pks: &[Integer],
) -> Result<VerifyShuffleResult, ShuffleError> {
    let upper_n = upper_cs.len();
    if upper_n < 2 || upper_n > Integer::from(ep.q() - Integer::three()) {
        return Err(ShuffleError::WrongCyphertextPrimeLen(upper_n));
    }
    if upper_c_primes.len() != upper_n {
        return Err(ShuffleError::DifferentCyphertextPrimeLen);
    }
    let l = upper_cs[0].phis.len();
    let k = pks.len();
    if l == 0 {
        return Err(ShuffleError::LPositive(l));
    }
    if l > k {
        return Err(ShuffleError::LSmallerOrEqualK(l, k));
    }
    for (i, c) in upper_cs.iter().enumerate() {
        if c.phis.len() != l {
            return Err(ShuffleError::NotSameLInCyphertexts {
                name: "C",
                i,
                phis_len: c.phis.len(),
                expected_size: l,
            });
        }
    }
    for (i, c) in upper_c_primes.iter().enumerate() {
        if c.phis.len() != l {
            return Err(ShuffleError::NotSameLInCyphertexts {
                name: "C'",
                i,
                phis_len: c.phis.len(),
                expected_size: l,
            });
        }
    }
    let (_m, n) = Matrix::<Integer>::get_matrix_dimensions(upper_n);
    let ck = CommitmentKey::get_verifiable_commitment_key(ep, n)
        .map_err(ShuffleError::VerifiableCommitmentKeyError)?;
    let context = ArgumentContext::new(ep, pks, &ck);
    let shuffle_statement = ShuffleStatement::new(upper_cs, upper_c_primes).map_err(|e| {
        ShuffleError::ShuffleStatement {
            source: Box::new(e),
        }
    })?;
    verify_shuffle_argument(
        &context,
        &ShuffleArgumentVerifyInput::new(&context, &shuffle_statement, shuffle_argument).map_err(
            |e| ShuffleError::ShuffleArgumentInput {
                source: Box::new(e),
            },
        )?,
    )
    .map(|r| VerifyShuffleResult {
        verify_shuffle_argument_result: r,
    })
    .map_err(|e| ShuffleError::VerifyShuffleArgument {
        source: Box::new(e),
    })
}

impl MixNetResultTrait for VerifyShuffleResult {
    fn is_ok(&self) -> bool {
        self.verify_shuffle_argument_result.is_ok()
    }
}

impl Display for VerifyShuffleResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.verify_shuffle_argument_result.fmt(f)
    }
}
