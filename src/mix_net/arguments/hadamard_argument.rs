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

//! Module implementing the verification for the Hadamrd Argument (§9.3.4)

use std::{ fmt::Display, iter::once };

use thiserror::Error;

use crate::{
    integer::MPInteger,
    mix_net::{ commitments::{ get_commitment, CommitmentError }, MixNetResultTrait },
    Constants,
    HashError,
    HashableMessage,
    Operations,
    RecursiveHashTrait,
};

use super::{
    zero_argument::{
        verify_zero_argument,
        ZeroArgument,
        ZeroArgumentError,
        ZeroArgumentResult,
        ZeroArgumentVerifyInput,
        ZeroStatement,
    },
    ArgumentContext,
};

/// Statement in input of the verify algorithm
#[derive(Debug, Clone)]
pub struct HadamardStatement {
    cs_upper_a: Vec<MPInteger>,
    c_b: MPInteger,
}

/// Argument in input of the verify algorithm
#[derive(Debug, Clone)]
pub struct HadamardArgument {
    cs_upper_b: Vec<MPInteger>,
    zero_argument: ZeroArgument,
}

/// Input of the verify algorithm
#[derive(Debug, Clone)]
pub struct HadamardArgumentVerifyInput<'a> {
    statement: &'a HadamardStatement,
    argument: &'a HadamardArgument,
}

/// Result of the verify algorithm, according to the specifications
#[derive(Debug, Eq, PartialEq)]
pub struct HadamardArgumentResult {
    c_upper_b_0_is_c_upper_a_0: bool,
    c_upper_b_m_minus_1_is_c_b: bool,
    zero_argument: ZeroArgumentResult,
}

/// Error during the process
#[derive(Error, Debug)]
pub enum HadamardArgumentError {
    #[error("Commitment vectors c_B must be like m of zero argument")]
    CommitmentVectorNotCorrectLen,
    #[error("m in statement and argument are not the same")]
    MInStatementAndArguemntNotSame,
    //#[error("Exponent vectors a' and b' have not the same size")]
    //ExponentVectorNotSameLen,
    //#[error(
    //    "Commitment vector c_d has not the size 2*m + 1 where m={0}"
    //)] CommitmentVectorNotCorrectSize(usize),
    #[error("HashError: {0}")] HashError(#[from] HashError),
    #[error("CommitmentError: {0}")] CommitmentError(#[from] CommitmentError),
    #[error("ZeroArgumentError: {0}")] ZeroArgumentError(#[from] ZeroArgumentError),
}

pub fn verify_hadamard_argument(
    context: &ArgumentContext,
    input: &HadamardArgumentVerifyInput
) -> Result<HadamardArgumentResult, HadamardArgumentError> {
    let statement = input.statement;
    let argument = input.argument;
    let m = argument.m();
    let n = argument.n();
    let p = context.ep.p();
    let q = context.ep.q();

    let x = get_x(context, statement, argument)?;
    let y = get_y(context, statement, argument)?;

    let x_powers = (0..m).map(|i| x.mod_exponentiate(&MPInteger::from(i), q)).collect::<Vec<_>>();

    let cs_upper_d = argument.cs_upper_b
        .iter()
        .take(m - 1)
        .zip(x_powers.iter().skip(1))
        .map(|(c_b_i, x_i_plus_1)| { c_b_i.mod_exponentiate(x_i_plus_1, p) })
        .collect::<Vec<_>>();
    let c_upper_d = argument.cs_upper_b
        .iter()
        .zip(x_powers.iter())
        .skip(1)
        .map(|(c_b_i, x_i_plus_1)| { c_b_i.mod_exponentiate(x_i_plus_1, p) })
        .fold(MPInteger::one().clone(), |acc, v| acc.mod_multiply(&v, p));

    let minus_1_vec = vec![MPInteger::from(q-MPInteger::one()); n];
    let c_minus_1 = get_commitment(
        &context.ep,
        &minus_1_vec,
        MPInteger::zero(),
        &context.ck
    ).map_err(HadamardArgumentError::CommitmentError)?;

    let zero_statement_input_cs_upper_a = statement.cs_upper_a
        .iter()
        .skip(1)
        .chain(once(&c_minus_1))
        .cloned()
        .collect::<Vec<_>>();
    let zero_statement_input_cs_upper_b = cs_upper_d
        .iter()
        .chain(once(&c_upper_d))
        .cloned()
        .collect::<Vec<_>>();
    let zero_statement = ZeroStatement::new(
        &zero_statement_input_cs_upper_a,
        &zero_statement_input_cs_upper_b,
        &y
    ).map_err(HadamardArgumentError::ZeroArgumentError)?;
    let zero_inputs = ZeroArgumentVerifyInput::new(
        &zero_statement,
        &argument.zero_argument
    ).map_err(HadamardArgumentError::ZeroArgumentError)?;

    Ok(HadamardArgumentResult {
        c_upper_b_0_is_c_upper_a_0: argument.cs_upper_b[0] == statement.cs_upper_a[0],
        c_upper_b_m_minus_1_is_c_b: argument.cs_upper_b[m - 1] == statement.c_b,
        zero_argument: verify_zero_argument(context, &zero_inputs).map_err(
            HadamardArgumentError::ZeroArgumentError
        )?,
    })
}

fn get_x(
    context: &ArgumentContext,
    statement: &HadamardStatement,
    argument: &HadamardArgument
) -> Result<MPInteger, HadamardArgumentError> {
    Ok(
        HashableMessage::from(get_hashable_vector_for_x(context, statement, argument))
            .recursive_hash()
            .map_err(HadamardArgumentError::HashError)?
            .into_mp_integer()
    )
}

fn get_y(
    context: &ArgumentContext,
    statement: &HadamardStatement,
    argument: &HadamardArgument
) -> Result<MPInteger, HadamardArgumentError> {
    let mut vec = get_hashable_vector_for_x(context, statement, argument);
    vec.insert(0, HashableMessage::from("1"));
    Ok(
        HashableMessage::from(vec)
            .recursive_hash()
            .map_err(HadamardArgumentError::HashError)?
            .into_mp_integer()
    )
}

fn get_hashable_vector_for_x<'a>(
    context: &'a ArgumentContext,
    statement: &'a HadamardStatement,
    argument: &'a HadamardArgument
) -> Vec<HashableMessage<'a>> {
    vec![
        HashableMessage::from(context.ep.p()),
        HashableMessage::from(context.ep.q()),
        HashableMessage::from(&context.pks),
        HashableMessage::from(&context.ck),
        HashableMessage::from(&statement.cs_upper_a),
        HashableMessage::from(&statement.c_b),
        HashableMessage::from(&argument.cs_upper_b)
    ]
}

impl MixNetResultTrait for HadamardArgumentResult {
    fn is_ok(&self) -> bool {
        self.c_upper_b_0_is_c_upper_a_0 &&
            self.c_upper_b_m_minus_1_is_c_b &&
            self.zero_argument.is_ok()
    }
}

impl Display for HadamardArgumentResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_ok() {
            return write!(f, "verification ok");
        }
        write!(
            f,
            "c_B_0 = c_A_0: {}, c_B_m-1 = c_B: {}, Zero Argument: {{ {} }}",
            self.c_upper_b_0_is_c_upper_a_0,
            self.c_upper_b_m_minus_1_is_c_b,
            self.zero_argument
        )
    }
}

impl HadamardStatement {
    /// New statement taking the ownership of the data
    ///
    /// Return error if the domain is wrong
    pub fn new_owned(
        cs_upper_a: Vec<MPInteger>,
        c_b: MPInteger
    ) -> Result<Self, HadamardArgumentError> {
        Ok(Self { cs_upper_a, c_b })
    }

    /// New statement cloning the data
    ///
    /// Return error if the domain is wrong
    pub fn new(cs_upper_a: &[MPInteger], c_b: &MPInteger) -> Result<Self, HadamardArgumentError> {
        Self::new_owned(cs_upper_a.to_vec(), c_b.clone())
    }

    pub fn m(&self) -> usize {
        self.cs_upper_a.len()
    }
}

impl HadamardArgument {
    /// New statement taking the ownership of the data
    ///
    /// Return error if the domain is wrong
    pub fn new_owned(
        cs_upper_b: Vec<MPInteger>,
        zero_argument: ZeroArgument
    ) -> Result<Self, HadamardArgumentError> {
        if zero_argument.cs_d.len() != 2 * cs_upper_b.len() + 1 {
            return Err(HadamardArgumentError::CommitmentVectorNotCorrectLen);
        }
        Ok(Self {
            cs_upper_b,
            zero_argument,
        })
    }

    /// New statement cloning the data
    ///
    /// Return error if the domain is wrong
    pub fn new(
        cs_upper_b: &[MPInteger],
        zero_argument: &ZeroArgument
    ) -> Result<Self, HadamardArgumentError> {
        Self::new_owned(cs_upper_b.to_vec(), zero_argument.clone())
    }

    pub fn m(&self) -> usize {
        self.cs_upper_b.len()
    }

    pub fn n(&self) -> usize {
        self.zero_argument.n()
    }
}

impl<'a> HadamardArgumentVerifyInput<'a> {
    /// New Input
    ///
    /// Return error if the domain is wrong
    pub fn new(
        statement: &'a HadamardStatement,
        argument: &'a HadamardArgument
    ) -> Result<Self, HadamardArgumentError> {
        if statement.m() != argument.m() {
            return Err(HadamardArgumentError::MInStatementAndArguemntNotSame);
        }
        Ok(Self { statement, argument })
    }
}

#[cfg(test)]
pub mod test {
    use std::path::Path;
    use super::*;
    use serde_json::Value;
    use super::super::test::context_from_json_value;
    use crate::test_json_data::{ json_array_value_to_array_mpinteger, json_value_to_mpinteger };
    use super::super::zero_argument::test::get_argument as get_zero_argument;

    fn get_test_cases() -> Vec<Value> {
        let test_file = Path::new("./")
            .join("test_data")
            .join("mixnet")
            .join("verify-hadamard-argument.json");
        let json = std::fs::read_to_string(test_file).unwrap();
        serde_json::from_str(&json).unwrap()
    }

    fn get_context(tc: &Value) -> ArgumentContext {
        context_from_json_value(&tc["context"])
    }

    fn get_statement(statement: &Value) -> HadamardStatement {
        HadamardStatement::new(
            &json_array_value_to_array_mpinteger(&statement["c_a"]),
            &json_value_to_mpinteger(&statement["c_b"])
        ).unwrap()
    }

    pub fn get_argument(argument: &Value) -> HadamardArgument {
        HadamardArgument::new(
            &json_array_value_to_array_mpinteger(&argument["cUpperB"]),
            &get_zero_argument(&argument["zero_argument"])
        ).unwrap()
    }

    #[test]
    fn test_verify() {
        for tc in get_test_cases().iter() {
            let context = get_context(tc);
            let statement = get_statement(&tc["input"]["statement"]);
            let argument = get_argument(&tc["input"]["argument"]);
            let input = HadamardArgumentVerifyInput::new(&statement, &argument).unwrap();
            let x_res = verify_hadamard_argument(&context, &input);
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
