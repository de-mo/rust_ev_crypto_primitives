// Copyright © 2023 Denis Morel

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

use super::{ElgamalError, ElgamalErrorRepr};
use crate::{ConstantsTrait, Integer, OperationsTrait};
use thiserror::Error;

#[derive(Error, Debug)]
pub(super) enum CombinePublicKeysError {
    #[error("{name} cannot be null")]
    NotNull { name: &'static str },
    #[error("Size of ph_{j} is {size}, but must be N={upper_n}")]
    SizePhiConsistency {
        j: usize,
        size: usize,
        upper_n: usize,
    },
    #[error("Size of combined keys is {size}, but must be N={upper_n}")]
    SizeResConsistency { size: usize, upper_n: usize },
}

/// Algorithm 8.13
pub fn combine_public_keys(
    p: &Integer,
    pks: &[Vec<Integer>],
) -> Result<Vec<Integer>, ElgamalError> {
    combine_public_keys_impl(p, pks)
        .map_err(ElgamalErrorRepr::from)
        .map_err(ElgamalError::from)
}

fn combine_public_keys_impl(
    p: &Integer,
    pks: &[Vec<Integer>],
) -> Result<Vec<Integer>, CombinePublicKeysError> {
    let s = pks.len();
    let upper_n = pks[0].len();
    if s == 0 {
        return Err(CombinePublicKeysError::NotNull { name: "s" });
    }
    if upper_n == 0 {
        return Err(CombinePublicKeysError::NotNull { name: "N" });
    }
    for (j, pks_j) in pks.iter().enumerate() {
        if pks_j.len() != upper_n {
            return Err(CombinePublicKeysError::SizePhiConsistency {
                j,
                size: pks_j.len(),
                upper_n,
            });
        }
    }

    let mut res = vec![Integer::one().clone(); upper_n];
    pks.iter().for_each(|pks_j| {
        res = pks_j
            .iter()
            .zip(res.iter())
            .map(|(pks_j_i, res_i)| res_i.mod_multiply(pks_j_i, p))
            .collect::<Vec<_>>()
    });

    if res.len() != upper_n {
        return Err(CombinePublicKeysError::SizeResConsistency {
            size: res.len(),
            upper_n,
        });
    }
    Ok(res)
}
