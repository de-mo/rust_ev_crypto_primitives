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

use std::fmt::Display;

use thiserror::Error;

use crate::{
    integer::MPInteger,
    mix_net::{ commitments::{ get_commitment, CommitmentError }, MixNetResultTrait },
    HashError,
    HashableMessage,
    Operations,
    RecursiveHashTrait,
};

use super::ArgumentContext;

/// Statement in input of the verify algorithm
#[derive(Debug, Clone)]
pub struct SingleValueProductStatement {
    pub c_a: MPInteger,
    pub b: MPInteger,
}

/// Argument in input of the verify algorithm
#[derive(Debug, Clone)]
pub struct SingleValueProductArgument {
    pub c_d: MPInteger,
    pub c_lower_delta: MPInteger,
    pub c_upper_delta: MPInteger,
    pub a_tilde: Vec<MPInteger>,
    pub b_tilde: Vec<MPInteger>,
    pub r_tilde: MPInteger,
    pub s_tilde: MPInteger,
}

/// Input of the verify algorithm
#[derive(Debug, Clone)]
pub struct SingleValueProductVerifyInput<'a> {
    statement: &'a SingleValueProductStatement,
    argument: &'a SingleValueProductArgument,
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
    #[error("HashError: {0}")] HashError(#[from] HashError),
    #[error("CommitmentError: {0}")] CommitmentError(#[from] CommitmentError),
}

impl SingleValueProductStatement {
    /// New statement taking the ownership of the data
    ///
    /// Return error if the domain is wrong
    pub fn new_owned(
        c_a: MPInteger,
        b: MPInteger
    ) -> Result<Self, SingleValueProductArgumentError> {
        Ok(Self { c_a, b })
    }

    /// New statement cloning the data
    ///
    /// Return error if the domain is wrong
    pub fn new(c_a: &MPInteger, b: &MPInteger) -> Result<Self, SingleValueProductArgumentError> {
        Self::new_owned(c_a.clone(), b.clone())
    }
}

impl SingleValueProductArgument {
    /// New argument taking the ownership of the data
    ///
    /// Return error if the domain is wrong
    pub fn new_owned(
        c_d: MPInteger,
        c_lower_delta: MPInteger,
        c_upper_delta: MPInteger,
        a_tilde: Vec<MPInteger>,
        b_tilde: Vec<MPInteger>,
        r_tilde: MPInteger,
        s_tilde: MPInteger
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

    /// New argument cloning the data
    ///
    /// Return error if the domain is wrong
    pub fn new(
        c_d: &MPInteger,
        c_lower_delta: &MPInteger,
        c_upper_delta: &MPInteger,
        a_tilde: &[MPInteger],
        b_tilde: &[MPInteger],
        r_tilde: &MPInteger,
        s_tilde: &MPInteger
    ) -> Result<Self, SingleValueProductArgumentError> {
        Self::new_owned(
            c_d.clone(),
            c_lower_delta.clone(),
            c_upper_delta.clone(),
            a_tilde.to_vec(),
            b_tilde.to_vec(),
            r_tilde.clone(),
            s_tilde.clone()
        )
    }
}

impl<'a> SingleValueProductVerifyInput<'a> {
    /// New Input
    ///
    /// Return error if the domain is wrong
    pub fn new(
        statement: &'a SingleValueProductStatement,
        argument: &'a SingleValueProductArgument
    ) -> Result<Self, SingleValueProductArgumentError> {
        Ok(Self { statement, argument })
    }
}

/// Algorithm 9.26
pub fn verify_single_value_product_argument(
    context: &ArgumentContext,
    input: &SingleValueProductVerifyInput<'_>
) -> Result<SingleValueProductArgumentResult, SingleValueProductArgumentError> {
    let statement = input.statement;
    let argument = input.argument;
    let p = context.ep.p();
    let q = context.ep.q();
    let n = argument.a_tilde.len();

    let x = get_x(context, statement, argument)?;

    let prod_upper_c_a = statement.c_a.mod_exponentiate(&x, p).mod_multiply(&argument.c_d, p);
    let comm_upper_a = get_commitment(
        &context.ep,
        &argument.a_tilde,
        &argument.r_tilde,
        &context.ck
    ).map_err(SingleValueProductArgumentError::CommitmentError)?;
    let verif_upper_a = prod_upper_c_a == comm_upper_a;

    let prod_delta = argument.c_upper_delta
        .mod_exponentiate(&x, p)
        .mod_multiply(&argument.c_lower_delta, p);
    let e: Vec<MPInteger> = argument.a_tilde
        .iter()
        .skip(1)
        .zip(
            argument.b_tilde
                .iter()
                .skip(1)
                .zip(argument.b_tilde.iter().take(n - 1))
        )
        .map(
            |(a_i_plus_1, (b_i_plus_1, b_i))|
                x.mod_multiply(b_i_plus_1, q) - b_i.mod_multiply(a_i_plus_1, q).modulo(q)
        )
        .collect();
    let comm_delta = get_commitment(&context.ep, &e, &argument.s_tilde, &context.ck).map_err(
        SingleValueProductArgumentError::CommitmentError
    )?;
    let verif_delta = prod_delta == comm_delta;

    let verif_upper_b =
        argument.b_tilde[0] == argument.a_tilde[0] &&
        argument.b_tilde[n - 1] == x.mod_multiply(&statement.b, q);

    Ok(SingleValueProductArgumentResult { verif_upper_a, verif_delta, verif_upper_b })
}

fn get_x(
    context: &ArgumentContext,
    statement: &SingleValueProductStatement,
    argument: &SingleValueProductArgument
) -> Result<MPInteger, SingleValueProductArgumentError> {
    Ok(
        HashableMessage::from(
            vec![
                HashableMessage::from(context.ep.p()),
                HashableMessage::from(context.ep.q()),
                HashableMessage::from(&context.pks),
                HashableMessage::from(&context.ck),
                HashableMessage::from(&argument.c_upper_delta),
                HashableMessage::from(&argument.c_lower_delta),
                HashableMessage::from(&argument.c_d),
                HashableMessage::from(&statement.b),
                HashableMessage::from(&statement.c_a)
            ]
        )
            .recursive_hash()
            .map_err(SingleValueProductArgumentError::HashError)?
            .into_mp_integer()
    )
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
            self.verif_upper_a,
            self.verif_delta,
            self.verif_upper_b
        )
    }
}

#[cfg(test)]
pub mod test {
    use std::path::Path;
    use super::*;
    use serde_json::Value;
    use super::super::test::context_from_json_value;
    use crate::test_json_data::{ json_array_value_to_array_mpinteger, json_value_to_mpinteger };

    fn get_test_cases() -> Vec<Value> {
        let test_file = Path::new("./")
            .join("test_data")
            .join("mixnet")
            .join("verify-single-value-product-argument.json");
        let json = std::fs::read_to_string(test_file).unwrap();
        serde_json::from_str(&json).unwrap()
    }

    fn get_context(tc: &Value) -> ArgumentContext {
        context_from_json_value(&tc["context"])
    }

    fn get_statement(statement: &Value) -> SingleValueProductStatement {
        SingleValueProductStatement::new_owned(
            json_value_to_mpinteger(&statement["c_a"]),
            json_value_to_mpinteger(&statement["b"])
        ).unwrap()
    }

    pub fn get_argument(argument: &Value) -> SingleValueProductArgument {
        SingleValueProductArgument::new_owned(
            json_value_to_mpinteger(&argument["c_d"]),
            json_value_to_mpinteger(&argument["c_lower_delta"]),
            json_value_to_mpinteger(&argument["c_upper_delta"]),
            json_array_value_to_array_mpinteger(&argument["a_tilde"]),
            json_array_value_to_array_mpinteger(&argument["b_tilde"]),
            json_value_to_mpinteger(&argument["r_tilde"]),
            json_value_to_mpinteger(&argument["s_tilde"])
        ).unwrap()
    }

    #[test]
    fn test_get_x() {
        for tc in get_test_cases().iter() {
            let statement = get_statement(&tc["input"]["statement"]);
            let argument = get_argument(&tc["input"]["argument"]);
            let x_res = get_x(&get_context(tc), &statement, &argument);
            assert!(x_res.is_ok(), "Error unwraping {}: {}", tc["description"], x_res.unwrap_err());
            assert_eq!(
                x_res.unwrap(),
                json_value_to_mpinteger(&tc["output"]["x"]),
                "{}",
                tc["description"]
            );
        }
    }

    #[test]
    fn test_verify() {
        for tc in get_test_cases().iter() {
            let statement = get_statement(&tc["input"]["statement"]);
            let argument = get_argument(&tc["input"]["argument"]);
            let input = SingleValueProductVerifyInput::new(&statement, &argument).unwrap();
            let x_res = verify_single_value_product_argument(&get_context(tc), &input);
            assert!(x_res.is_ok(), "Error unwraping {}: {}", tc["description"], x_res.unwrap_err());
            assert!(
                x_res.as_ref().unwrap().is_ok(),
                "Verification for {} not ok: {}",
                tc["description"],
                x_res.as_ref().unwrap()
            );
        }
    }
}
