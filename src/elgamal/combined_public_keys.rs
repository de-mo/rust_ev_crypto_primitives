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

use super::ElgamalError;
use crate::{ConstantsTrait, Integer, OperationsTrait};

/// Algorithm 8.13
pub fn combine_public_keys(
    p: &Integer,
    pks: &[Vec<Integer>],
) -> Result<Vec<Integer>, ElgamalError> {
    let s = pks.len();
    let upper_n = pks[0].len();
    if s == 0 {
        return Err(ElgamalError::CombinedPublicKeysInput(
            "s must not be null".to_string(),
        ));
    }
    if upper_n == 0 {
        return Err(ElgamalError::CombinedPublicKeysInput(
            "N must not be null".to_string(),
        ));
    }
    for (j, pks_j) in pks.iter().enumerate() {
        if pks_j.len() != upper_n {
            return Err(ElgamalError::CombinedPublicKeysInput(format!(
                "Size of ph_{} is {}, but must be N={}",
                j,
                pks_j.len(),
                upper_n
            )));
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
        return Err(ElgamalError::CombinedPublicKeysInput(format!(
            "Size of combined keys is {}, but must be N={}",
            res.len(),
            upper_n
        )));
    }
    Ok(res)
}
