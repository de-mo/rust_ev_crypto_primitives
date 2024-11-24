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

pub use hadamard_argument::{HadamardArgument, HadamardArgumentError};
pub use multi_exponentiation_argument::{
    MultiExponentiationArgument, MultiExponentiationArgumentError,
};
pub use product_argument::{ProductArgument, ProductArgumentError};
pub use shuffle_argument::{
    verify_shuffle_argument, ShuffleArgument, ShuffleArgumentError, ShuffleArgumentVerifyInput,
    ShuffleStatement, VerifyShuffleArgumentResult,
};
pub use single_value_product_argument::{
    SingleValueProductArgument, SingleValueProductArgumentError,
};
pub use zero_argument::{ZeroArgument, ZeroArgumentError};

use thiserror::Error;

use super::commitments::CommitmentKey;
use crate::{elgamal::EncryptionParameters, ConstantsTrait, Integer, OperationsTrait};

/// context for all arguments verification functions
#[derive(Clone, Debug)]
pub struct ArgumentContext<'a> {
    ep: &'a EncryptionParameters,
    pks: &'a [Integer],
    ck: &'a CommitmentKey,
}

#[derive(Error, Debug)]
pub enum StarMapError {
    #[error("vectors a and b have not the same size")]
    VectorNotSameLen,
}

pub fn star_map(
    q: &Integer,
    y: &Integer,
    a: &[Integer],
    b: &[Integer],
) -> Result<Integer, StarMapError> {
    if a.len() != b.len() {
        return Err(StarMapError::VectorNotSameLen);
    }
    Ok(a.iter()
        .zip(b.iter())
        .enumerate()
        .map(|(j, (a_j, b_j))| {
            a_j.mod_multiply(b_j, q)
                .mod_multiply(&y.mod_exponentiate(&Integer::from(j + 1), q), q)
        })
        .fold(Integer::zero().clone(), |acc, v| acc + v)
        .modulo(q))
}

impl<'a> ArgumentContext<'a> {
    /// New context cloning the data
    pub fn new(ep: &'a EncryptionParameters, pks: &'a [Integer], ck: &'a CommitmentKey) -> Self {
        Self { ep, pks, ck }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_json_data::{json_array_value_to_array_mpinteger, json_value_to_mpinteger};
    use serde_json::Value;
    use std::path::Path;

    pub struct EncryptionParametersValues(pub Integer, pub Integer, pub Integer);
    pub struct CommitmentKeyValues(pub Integer, pub Vec<Integer>);

    pub struct ContextValues(
        pub EncryptionParametersValues,
        Vec<Integer>,
        pub CommitmentKeyValues,
    );

    pub fn context_values(context: &Value) -> ContextValues {
        ContextValues(
            EncryptionParametersValues(
                json_value_to_mpinteger(&context["p"]),
                json_value_to_mpinteger(&context["q"]),
                json_value_to_mpinteger(&context["g"]),
            ),
            json_array_value_to_array_mpinteger(&context["pk"]),
            CommitmentKeyValues(
                json_value_to_mpinteger(&context["ck"]["h"]),
                json_array_value_to_array_mpinteger(&context["ck"]["g"]),
            ),
        )
    }

    pub fn ep_from_json_value(values: &EncryptionParametersValues) -> EncryptionParameters {
        EncryptionParameters::from((&values.0, &values.1, &values.2))
    }

    pub fn ck_from_json_value(values: &CommitmentKeyValues) -> CommitmentKey {
        CommitmentKey {
            h: values.0.clone(),
            gs: values.1.clone(),
        }
    }

    pub fn context_from_json_value<'a>(
        values: &'a ContextValues,
        ep: &'a EncryptionParameters,
        ck: &'a CommitmentKey,
    ) -> ArgumentContext<'a> {
        ArgumentContext::new(ep, &values.1, ck)
    }

    fn get_test_cases() -> Vec<Value> {
        let test_file = Path::new("./")
            .join("test_data")
            .join("mixnet")
            .join("bilinearMap.json");
        let json = std::fs::read_to_string(test_file).unwrap();
        serde_json::from_str(&json).unwrap()
    }

    fn get_input(tc: &Value) -> (Integer, Vec<Integer>, Vec<Integer>) {
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
            let context_values = context_values(&tc["context"]);
            let ep = ep_from_json_value(&context_values.0);
            let ck = ck_from_json_value(&context_values.2);
            let context = context_from_json_value(&context_values, &ep, &ck);
            let (y, a, b) = get_input(tc);
            let s_res = star_map(context.ep.q(), &y, &a, &b);
            assert!(
                s_res.is_ok(),
                "Error unwraping {}: {}",
                tc["description"],
                s_res.unwrap_err()
            );
            assert_eq!(
                s_res.unwrap(),
                json_value_to_mpinteger(&tc["output"]["value"]),
                "{}",
                tc["description"]
            );
        }
    }
}
