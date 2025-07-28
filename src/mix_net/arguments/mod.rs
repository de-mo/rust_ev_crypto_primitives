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

use super::commitments::CommitmentKey;
use crate::{
    elgamal::EncryptionParameters, integer::ModExponentiateError, ConstantsTrait, Integer,
    OperationsTrait,
};
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
use std::ops::ControlFlow;
use thiserror::Error;
pub use zero_argument::{ZeroArgument, ZeroArgumentError};

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
    #[error("Error calculating y^(j+1) mod p")]
    Exp { source: ModExponentiateError },
}

fn star_map(
    q: &Integer,
    y: &Integer,
    a: &[Integer],
    b: &[Integer],
) -> Result<Integer, StarMapError> {
    if a.len() != b.len() {
        return Err(StarMapError::VectorNotSameLen);
    }
    match a
        .iter()
        .zip(b.iter())
        .enumerate()
        .map(|(j, (a_j, b_j))| {
            y.mod_exponentiate(&Integer::from(j + 1), q)
                .map(|v| a_j.mod_multiply(b_j, q).mod_multiply(&v, q))
                .map_err(|e| StarMapError::Exp { source: e })
            //a_j.mod_multiply(b_j, q)
            //    .mod_multiply(&y.mod_exponentiate(&Integer::from(j + 1), q), q)
        })
        .try_fold(Integer::zero().clone(), |acc, v_res| match v_res {
            Ok(v) => ControlFlow::Continue(acc + v),
            Err(e) => ControlFlow::Break(e),
        }) {
        ControlFlow::Continue(v) => Ok(v.modulo(q)),
        ControlFlow::Break(e) => Err(e),
    }
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
    use crate::test_json_data::{
        get_test_cases_from_json_file, json_64_value_to_integer,
        json_array_64_value_to_array_integer, json_array_exa_value_to_array_integer,
        json_exa_value_to_integer, json_value_to_encryption_parameters,
    };
    use serde_json::Value;

    pub struct EncryptionParametersValues(pub Integer, pub Integer, pub Integer);
    pub struct CommitmentKeyValuesOld(pub Integer, pub Vec<Integer>);

    pub struct CommitmentKeyValues {
        pub h: Integer,
        pub gs: Vec<Integer>,
    }

    pub struct ContextValuesOld(
        pub EncryptionParametersValues,
        Vec<Integer>,
        pub CommitmentKeyValuesOld,
    );

    pub struct ContextValues {
        pub ep: EncryptionParameters,
        pub pk: Vec<Integer>,
        pub ck: CommitmentKey,
    }

    impl<'a> From<&'a ContextValues> for ArgumentContext<'a> {
        fn from(value: &'a ContextValues) -> Self {
            Self {
                ep: &value.ep,
                pks: &value.pk,
                ck: &value.ck,
            }
        }
    }

    impl From<&CommitmentKeyValues> for CommitmentKey {
        fn from(value: &CommitmentKeyValues) -> Self {
            CommitmentKey {
                h: value.h.clone(),
                gs: value.gs.clone(),
            }
        }
    }

    pub fn json_to_commitment_key_values(value: &Value) -> CommitmentKeyValues {
        CommitmentKeyValues {
            h: json_64_value_to_integer(&value["h"]),
            gs: json_array_64_value_to_array_integer(&value["g"]),
        }
    }

    pub fn json_to_commitment_key(value: &Value) -> CommitmentKey {
        CommitmentKey::from(&json_to_commitment_key_values(value))
    }

    pub fn json_to_context_values(value: &Value) -> ContextValues {
        ContextValues {
            ep: json_value_to_encryption_parameters(value),
            pk: json_array_64_value_to_array_integer(&value["pk"]),
            ck: json_to_commitment_key(&value["ck"]),
        }
    }

    pub fn context_values(context: &Value) -> ContextValuesOld {
        ContextValuesOld(
            EncryptionParametersValues(
                json_exa_value_to_integer(&context["p"]),
                json_exa_value_to_integer(&context["q"]),
                json_exa_value_to_integer(&context["g"]),
            ),
            json_array_exa_value_to_array_integer(&context["pk"]),
            CommitmentKeyValuesOld(
                json_exa_value_to_integer(&context["ck"]["h"]),
                json_array_exa_value_to_array_integer(&context["ck"]["g"]),
            ),
        )
    }

    pub fn ep_from_json_value(values: &EncryptionParametersValues) -> EncryptionParameters {
        EncryptionParameters::from((&values.0, &values.1, &values.2))
    }

    pub fn ck_from_json_value(values: &CommitmentKeyValuesOld) -> CommitmentKey {
        CommitmentKey {
            h: values.0.clone(),
            gs: values.1.clone(),
        }
    }

    pub fn context_from_json_value<'a>(
        values: &'a ContextValuesOld,
        ep: &'a EncryptionParameters,
        ck: &'a CommitmentKey,
    ) -> ArgumentContext<'a> {
        ArgumentContext::new(ep, &values.1, ck)
    }

    fn get_input(tc: &Value) -> (Integer, Vec<Integer>, Vec<Integer>) {
        let input = tc["input"].clone();
        (
            json_64_value_to_integer(&input["y"]),
            json_array_64_value_to_array_integer(&input["a"]),
            json_array_64_value_to_array_integer(&input["b"]),
        )
    }

    #[test]
    fn test_star_map() {
        for tc in get_test_cases_from_json_file("mixnet", "bilinearMap.json").iter() {
            let context_values = json_to_context_values(&tc["context"]);
            let context = ArgumentContext::from(&context_values);
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
                json_64_value_to_integer(&tc["output"]["value"]),
                "{}",
                tc["description"]
            );
        }
    }
}
