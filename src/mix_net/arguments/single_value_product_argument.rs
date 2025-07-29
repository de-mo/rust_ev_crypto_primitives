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

//! Module implementing the verification for the Single Value Product Argument (§9.3.6)

use super::ArgumentContext;
use crate::{
    integer::ModExponentiateError,
    mix_net::{
        commitments::{get_commitment, CommitmentError},
        MixNetResultTrait, MixnetError, MixnetErrorRepr,
    },
    HashError, HashableMessage, Integer, OperationsTrait, RecursiveHashTrait,
};
use std::fmt::Display;
use thiserror::Error;

/// Statement in input of the verify algorithm
#[derive(Debug, Clone)]
pub struct SingleValueProductStatement<'a> {
    pub c_a: &'a Integer,
    pub b: &'a Integer,
}

/// Argument in input of the verify algorithm
#[derive(Debug, Clone)]
pub struct SingleValueProductArgument<'a> {
    pub c_d: &'a Integer,
    pub c_lower_delta: &'a Integer,
    pub c_upper_delta: &'a Integer,
    pub a_tilde: &'a [Integer],
    pub b_tilde: &'a [Integer],
    pub r_tilde: &'a Integer,
    pub s_tilde: &'a Integer,
}

/// Input of the verify algorithm
#[derive(Debug, Clone)]
pub struct SingleValueProductVerifyInput<'a, 'b> {
    statement: &'a SingleValueProductStatement<'a>,
    argument: &'b SingleValueProductArgument<'b>,
}

/// Result of the verify algorithm, according to the specifications
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingleValueProductArgumentResult {
    verif_upper_a: bool,
    verif_delta: bool,
    verif_upper_b: bool,
}

/// Error during the process
#[derive(Error, Debug)]
pub enum SingleValueProductArgumentError {
    #[error("Exponent vectors a_tilde and b_tilde have not the same size")]
    ExponentVectorNotSameLen,
    #[error("Exponent vectors a_tilde and b_tilde to small")]
    TooSmallExponentVector,
    #[error("Error calculating the product C_a")]
    ProdCA { source: ModExponentiateError },
    #[error("Error for x")]
    X { source: HashError },
    #[error("error calculation Commitment A")]
    CommitmentA { source: CommitmentError },
    #[error("Error calculating the product of Delta")]
    ProdDelta { source: ModExponentiateError },
    #[error("error calculation Commitment Delta")]
    CommitmentDelta { source: CommitmentError },
}

impl<'a> SingleValueProductStatement<'a> {
    /// New statement cloning the data
    ///
    /// Return error if the domain is wrong
    pub fn new(c_a: &'a Integer, b: &'a Integer) -> Result<Self, SingleValueProductArgumentError> {
        Ok(Self { c_a, b })
    }
}

impl<'a> SingleValueProductArgument<'a> {
    /// New argument
    ///
    /// Return error if the domain is wrong
    pub fn new(
        c_d: &'a Integer,
        c_lower_delta: &'a Integer,
        c_upper_delta: &'a Integer,
        a_tilde: &'a [Integer],
        b_tilde: &'a [Integer],
        r_tilde: &'a Integer,
        s_tilde: &'a Integer,
    ) -> Result<Self, MixnetError> {
        Self::new_impl(
            c_d,
            c_lower_delta,
            c_upper_delta,
            a_tilde,
            b_tilde,
            r_tilde,
            s_tilde,
        )
        .map_err(MixnetErrorRepr::from)
        .map_err(|e| MixnetError {
            source: Box::new(e),
        })
    }

    fn new_impl(
        c_d: &'a Integer,
        c_lower_delta: &'a Integer,
        c_upper_delta: &'a Integer,
        a_tilde: &'a [Integer],
        b_tilde: &'a [Integer],
        r_tilde: &'a Integer,
        s_tilde: &'a Integer,
    ) -> Result<Self, SingleValueProductArgumentError> {
        if a_tilde.len() != b_tilde.len() {
            return Err(SingleValueProductArgumentError::ExponentVectorNotSameLen);
        }
        if a_tilde.len() < 2 {
            return Err(SingleValueProductArgumentError::TooSmallExponentVector);
        }
        Ok(Self {
            c_d,
            c_lower_delta,
            c_upper_delta,
            a_tilde,
            b_tilde,
            r_tilde,
            s_tilde,
        })
    }
}

impl<'a, 'b> SingleValueProductVerifyInput<'a, 'b> {
    /// New Input
    ///
    /// Return error if the domain is wrong
    pub fn new(
        statement: &'a SingleValueProductStatement<'a>,
        argument: &'b SingleValueProductArgument<'b>,
    ) -> Result<Self, SingleValueProductArgumentError> {
        Ok(Self {
            statement,
            argument,
        })
    }
}

/// Algorithm 9.26
pub fn verify_single_value_product_argument(
    context: &ArgumentContext,
    input: &SingleValueProductVerifyInput,
) -> Result<SingleValueProductArgumentResult, SingleValueProductArgumentError> {
    let statement = input.statement;
    let argument = input.argument;
    let p = context.ep.p();
    let q = context.ep.q();
    let n = argument.a_tilde.len();

    let x = get_x(context, statement, argument)
        .map_err(|e| SingleValueProductArgumentError::X { source: e })?;

    let prod_upper_c_a = statement
        .c_a
        .mod_exponentiate(&x, p)
        .map_err(|e| SingleValueProductArgumentError::ProdCA { source: e })?
        .mod_multiply(argument.c_d, p);
    let comm_upper_a = get_commitment(context.ep, argument.a_tilde, argument.r_tilde, context.ck)
        .map_err(|e| SingleValueProductArgumentError::CommitmentA { source: e })?;
    let verif_upper_a = prod_upper_c_a == comm_upper_a;

    let prod_delta = argument
        .c_upper_delta
        .mod_exponentiate(&x, p)
        .map_err(|e| SingleValueProductArgumentError::ProdDelta { source: e })?
        .mod_multiply(argument.c_lower_delta, p);
    let e: Vec<Integer> = argument
        .a_tilde
        .iter()
        .skip(1)
        .zip(
            argument
                .b_tilde
                .iter()
                .skip(1)
                .zip(argument.b_tilde.iter().take(n - 1)),
        )
        .map(|(a_i_plus_1, (b_i_plus_1, b_i))| {
            x.mod_multiply(b_i_plus_1, q)
                .mod_sub(&b_i.mod_multiply(a_i_plus_1, q), q)
        })
        .collect();
    let comm_delta = get_commitment(context.ep, &e, argument.s_tilde, context.ck)
        .map_err(|e| SingleValueProductArgumentError::CommitmentDelta { source: e })?;
    let verif_delta = prod_delta == comm_delta;

    let verif_upper_b = argument.b_tilde[0] == argument.a_tilde[0]
        && argument.b_tilde[n - 1] == x.mod_multiply(statement.b, q);

    Ok(SingleValueProductArgumentResult {
        verif_upper_a,
        verif_delta,
        verif_upper_b,
    })
}

fn get_x(
    context: &ArgumentContext,
    statement: &SingleValueProductStatement,
    argument: &SingleValueProductArgument,
) -> Result<Integer, HashError> {
    Ok(HashableMessage::from(vec![
        HashableMessage::from(context.ep.p()),
        HashableMessage::from(context.ep.q()),
        HashableMessage::from(context.pks),
        HashableMessage::from(context.ck),
        HashableMessage::from(argument.c_upper_delta),
        HashableMessage::from(argument.c_lower_delta),
        HashableMessage::from(argument.c_d),
        HashableMessage::from(statement.b),
        HashableMessage::from(statement.c_a),
    ])
    .recursive_hash()?
    .into_integer())
}

impl MixNetResultTrait for SingleValueProductArgumentResult {
    fn is_ok(&self) -> bool {
        self.verif_upper_a && self.verif_upper_b && self.verif_delta
    }
}

impl Display for SingleValueProductArgumentResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_ok() {
            return write!(f, "verification ok");
        }
        write!(
            f,
            "verifA: {}, verifDelta: {}, verifB {}",
            self.verif_upper_a, self.verif_delta, self.verif_upper_b
        )
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::mix_net::arguments::test_json_data::json_to_context_values;
    use crate::test_json_data::{
        get_test_cases_from_json_file, json_64_value_to_integer,
        json_array_64_value_to_array_integer,
    };
    use serde_json::Value;

    pub struct SVPStatementValues(pub Integer, pub Integer);
    pub struct SVPArgumentValues(
        pub Integer,
        pub Integer,
        pub Integer,
        pub Vec<Integer>,
        pub Vec<Integer>,
        pub Integer,
        pub Integer,
    );

    fn get_statement_values(statement: &Value) -> SVPStatementValues {
        SVPStatementValues(
            json_64_value_to_integer(&statement["c_a"]),
            json_64_value_to_integer(&statement["b"]),
        )
    }

    fn get_statement(values: &SVPStatementValues) -> SingleValueProductStatement<'_> {
        SingleValueProductStatement::new(&values.0, &values.1).unwrap()
    }

    pub fn get_argument_values(argument: &Value) -> SVPArgumentValues {
        SVPArgumentValues(
            json_64_value_to_integer(&argument["c_d"]),
            json_64_value_to_integer(&argument["c_lower_delta"]),
            json_64_value_to_integer(&argument["c_upper_delta"]),
            json_array_64_value_to_array_integer(&argument["a_tilde"]),
            json_array_64_value_to_array_integer(&argument["b_tilde"]),
            json_64_value_to_integer(&argument["r_tilde"]),
            json_64_value_to_integer(&argument["s_tilde"]),
        )
    }

    pub fn get_argument(values: &SVPArgumentValues) -> SingleValueProductArgument<'_> {
        SingleValueProductArgument::new(
            &values.0, &values.1, &values.2, &values.3, &values.4, &values.5, &values.6,
        )
        .unwrap()
    }

    #[test]
    fn test_verify() {
        for tc in
            get_test_cases_from_json_file("mixnet", "verify-single-value-product-argument.json")
                .iter()
        {
            let context_values = json_to_context_values(&tc["context"]);
            let context = ArgumentContext::from(&context_values);
            let statement_values = get_statement_values(&tc["input"]["statement"]);
            let statement = get_statement(&statement_values);
            let argument_values = get_argument_values(&tc["input"]["argument"]);
            let argument = get_argument(&argument_values);
            let input = SingleValueProductVerifyInput::new(&statement, &argument).unwrap();
            let x_res = get_x(&context, &statement, &argument);
            assert!(
                x_res.is_ok(),
                "Error unwraping x {}: {}",
                tc["description"],
                x_res.unwrap_err()
            );
            assert_eq!(
                x_res.unwrap(),
                json_64_value_to_integer(&tc["output"]["x"]),
                "Not same x: {}",
                tc["description"]
            );
            let x_res = verify_single_value_product_argument(&context, &input);
            assert!(
                x_res.is_ok(),
                "Error unwraping {}: {}",
                tc["description"],
                x_res.unwrap_err()
            );
            assert!(
                x_res.as_ref().unwrap().is_ok(),
                "Verification for {} not ok: {}",
                tc["description"],
                x_res.as_ref().unwrap()
            );
        }
    }
}
