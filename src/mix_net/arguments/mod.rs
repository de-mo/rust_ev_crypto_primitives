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

mod hadamard_argument;
mod multi_exponentiation_argument;
mod product_argument;
mod shuffle_argument;
mod single_value_product_argument;
mod zero_argument;

pub use shuffle_argument::{
    verify_shuffle_argument,
    ShuffleArgument,
    ShuffleStatement,
    ShuffleArgumentVerifyInput,
    ShuffleArgumentError,
    VerifyShuffleArgumentResult,
};
pub use hadamard_argument::HadamardArgument;
pub use multi_exponentiation_argument::MultiExponentiationArgument;
pub use product_argument::ProductArgument;
pub use single_value_product_argument::SingleValueProductArgument;
pub use zero_argument::ZeroArgument;

use thiserror::Error;

use super::commitments::CommitmentKey;
use crate::{ integer::MPInteger, Constants, EncryptionParameters, Operations };

/// context for all arguments verification functions
#[derive(Clone, Debug)]
pub struct ArgumentContext {
    ep: EncryptionParameters,
    pks: Vec<MPInteger>,
    ck: CommitmentKey,
}

#[derive(Error, Debug)]
pub enum StarMapError {
    #[error("vectors a and b have not the same size")]
    VectorNotSameLen,
}

pub fn star_map(
    q: &MPInteger,
    y: &MPInteger,
    a: &[MPInteger],
    b: &[MPInteger]
) -> Result<MPInteger, StarMapError> {
    if a.len() != b.len() {
        return Err(StarMapError::VectorNotSameLen);
    }
    Ok(
        a
            .iter()
            .zip(b.iter())
            .enumerate()
            .map(|(j, (a_j, b_j))|
                a_j
                    .mod_multiply(b_j, q)
                    .mod_multiply(&y.mod_exponentiate(&MPInteger::from(j + 1), q), q)
            )
            .fold(MPInteger::zero().clone(), |acc, v| acc + v)
            .modulo(q)
    )
}

impl ArgumentContext {
    /// New context taking the ownership of the data
    pub fn new_owned(ep: EncryptionParameters, pks: Vec<MPInteger>, ck: CommitmentKey) -> Self {
        Self { ep, pks, ck }
    }

    /// New context cloning the data
    pub fn new(ep: &EncryptionParameters, pks: &[MPInteger], ck: &CommitmentKey) -> Self {
        Self::new_owned(ep.clone(), pks.to_vec(), ck.clone())
    }
}

#[cfg(test)]
mod test {
    use std::path::Path;
    use crate::test_json_data::{ json_array_value_to_array_mpinteger, json_value_to_mpinteger };
    use serde_json::Value;
    use super::*;

    pub fn context_from_json_value(context: &Value) -> ArgumentContext {
        ArgumentContext::new(
            &EncryptionParameters::from((
                &json_value_to_mpinteger(&context["p"]),
                &json_value_to_mpinteger(&context["q"]),
                &json_value_to_mpinteger(&context["g"]),
            )),
            &&json_array_value_to_array_mpinteger(&context["pk"]),
            &(CommitmentKey {
                h: json_value_to_mpinteger(&context["ck"]["h"]),
                gs: json_array_value_to_array_mpinteger(&context["ck"]["g"]),
            })
        )
    }

    fn get_test_cases() -> Vec<Value> {
        let test_file = Path::new("./").join("test_data").join("mixnet").join("bilinearMap.json");
        let json = std::fs::read_to_string(test_file).unwrap();
        serde_json::from_str(&json).unwrap()
    }

    fn get_context(tc: &Value) -> ArgumentContext {
        context_from_json_value(&tc["context"])
    }

    fn get_input(tc: &Value) -> (MPInteger, Vec<MPInteger>, Vec<MPInteger>) {
        let input = tc["input"].clone();
        (
            json_value_to_mpinteger(&input["y"]),
            json_array_value_to_array_mpinteger(&input["a"]),
            json_array_value_to_array_mpinteger(&input["b"]),
        )
    }

    #[test]
    fn test_star_map() {
        for tc in get_test_cases().iter() {
            let context = get_context(tc);
            let (y, a, b) = get_input(tc);
            let s_res = star_map(context.ep.q(), &y, &a, &b);
            assert!(s_res.is_ok(), "Error unwraping {}: {}", tc["description"], s_res.unwrap_err());
            assert_eq!(
                s_res.unwrap(),
                json_value_to_mpinteger(&tc["output"]["value"]),
                "{}",
                tc["description"]
            );
        }
    }
}
