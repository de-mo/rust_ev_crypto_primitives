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
    arguments::{verify_shuffle_argument, VerifyShuffleArgumentResult},
    CommitmentKey, Matrix, ShuffleArgument,
};
use crate::{
    integer::{Constants, MPInteger},
    zero_knowledge_proofs::Cyphertext,
    EncryptionParameters,
};
use thiserror::Error;

/// The result of the verification of the shuffle
pub struct VerifyShuffleResult {
    pub verify_shuffle_argument_result: VerifyShuffleArgumentResult,
}

#[derive(Error, Debug)]
pub enum ShuffleError {
    #[error("The length of C' is not the same than the expected length of C")]
    DifferentCyphertextPrimeLen,
    #[error(
        "In the cypthertexts {0} at position {1}, the size of phis {2} is not the same than the expected size {3}"
    )]
    NotSameLInCyphertexts(String, usize, usize, usize),
    #[error("Wrong size of N. Must be greater or equal that 2 and less or equal than q")]
    WrongCyphertextPrimeLen,
    #[error("l={0} must be smaller or equal to k={1}")]
    LSmallerOrEqualK(usize, usize),
    #[error("l must be positive")]
    LPositive(usize),
    #[error(transparent)]
    VerifiableCommitmentKeyError(#[from] super::CommitmentError),
    #[error(transparent)]
    VerifyShuffleArgumentError(#[from] super::VerifyShuffleArgumentError),
}

/// Verify Shuffle according to the specification of Swiss Post (algorithm 9.2)
///
/// # return
/// A stucture containing the result of the verification
/// An error is something goes wrong
pub fn verify_shuffle(
    ep: &EncryptionParameters,
    upper_cs: &[Cyphertext],
    upper_c_primes: &[Cyphertext],
    shuffle_argument: &ShuffleArgument,
    pks: &[MPInteger],
) -> Result<VerifyShuffleResult, ShuffleError> {
    let upper_n = upper_cs.len();
    if upper_n < 2 || upper_n > MPInteger::from(ep.q() - MPInteger::three()) {
        return Err(ShuffleError::WrongCyphertextPrimeLen);
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
            return Err(ShuffleError::NotSameLInCyphertexts(
                "C".to_string(),
                i,
                c.phis.len(),
                l,
            ));
        }
    }
    for (i, c) in upper_c_primes.iter().enumerate() {
        if c.phis.len() != l {
            return Err(ShuffleError::NotSameLInCyphertexts(
                "C".to_string(),
                i,
                c.phis.len(),
                l,
            ));
        }
    }
    let (m, n) = Matrix::get_matrix_dimensions(upper_n);
    let ck = CommitmentKey::get_verifiable_commitment_key(ep, n)
        .map_err(ShuffleError::VerifiableCommitmentKeyError)?;
    let shuffle_statement = (upper_cs, upper_c_primes);
    verify_shuffle_argument(ep, pks, &ck, shuffle_statement, shuffle_argument, (m, n))
        .map(|r| VerifyShuffleResult {
            verify_shuffle_argument_result: r,
        })
        .map_err(ShuffleError::VerifyShuffleArgumentError)
}
