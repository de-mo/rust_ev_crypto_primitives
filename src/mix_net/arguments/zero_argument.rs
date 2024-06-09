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

//! Module implementing the verification for the Zero Argument (§9.3.5)

use std::fmt::Display;

use thiserror::Error;

use crate::{
    integer::{ Constants, MPInteger },
    mix_net::{ commitments::{ get_commitment, CommitmentError }, MixNetResultTrait },
    HashError,
    HashableMessage,
    Operations,
    RecursiveHashTrait,
};
use super::{ star_map, ArgumentContext, StarMapError };

/// Statement in input of the verify algorithm
#[derive(Debug, Clone)]
pub struct ZeroStatement<'a> {
    cs_upper_a: &'a [MPInteger],
    cs_upper_b: &'a [MPInteger],
    y: &'a MPInteger,
}

/// Argument in input of the verify algorithm
#[derive(Debug, Clone)]
pub struct ZeroArgument<'a> {
    pub c_upper_a_0: &'a MPInteger,
    pub c_upper_b_m: &'a MPInteger,
    pub cs_d: &'a [MPInteger],
    pub as_prime: &'a [MPInteger],
    pub bs_prime: &'a [MPInteger],
    pub r_prime: &'a MPInteger,
    pub s_prime: &'a MPInteger,
    pub t_prime: &'a MPInteger,
}

/// Input of the verify algorithm
#[derive(Debug, Clone)]
pub struct ZeroArgumentVerifyInput<'a, 'b> {
    statement: &'a ZeroStatement<'a>,
    argument: &'b ZeroArgument<'b>,
}

/// Result of the verify algorithm, according to the specifications
#[derive(Debug, Eq, PartialEq)]
pub struct ZeroArgumentResult {
    pub verif_upper_a: bool,
    pub verif_upper_b: bool,
    pub verif_upper_d: bool,
    pub verif_upper_c_d: bool,
}

/// Error during the process
#[derive(Error, Debug)]
pub enum ZeroArgumentError {
    #[error("Commitment vectors c_A and c_B have not the same size")]
    CommitmentVectorNotSameLen,
    #[error("Exponent vectors a' and b' have not the same size")]
    ExponentVectorNotSameLen,
    #[error(
        "Commitment vector c_d has not the size 2*m + 1 where m={0}"
    )] CommitmentVectorNotCorrectSize(usize),
    #[error("HashError: {0}")] HashError(#[from] HashError),
    #[error("CommitmentError: {0}")] CommitmentError(#[from] CommitmentError),
    #[error("StarMapError: {0}")] StarMapError(#[from] StarMapError),
}

/// Algorithm 9.23
pub fn verify_zero_argument(
    context: &ArgumentContext,
    input: &ZeroArgumentVerifyInput
) -> Result<ZeroArgumentResult, ZeroArgumentError> {
    let statement = input.statement;
    let argument = input.argument;
    let p = context.ep.p();
    let q = context.ep.q();
    let m = statement.m();

    let x = get_x(context, statement, argument)?;
    let x_powers: Vec<MPInteger> = (0..2 * m + 1)
        .map(|i| x.mod_exponentiate(&MPInteger::from(i), q))
        .collect();

    let verif_upper_c_d = &argument.cs_d[m + 1] == MPInteger::one();

    let prod_c_a = [argument.c_upper_a_0.clone()]
        .iter()
        .chain(statement.cs_upper_a.iter())
        .enumerate()
        .map(|(i, c)| c.mod_exponentiate(&x_powers[i], p))
        .fold(MPInteger::one().clone(), |acc, v| acc.mod_multiply(&v, p));
    let comm_a = get_commitment(
        &context.ep,
        &argument.as_prime,
        &argument.r_prime,
        &context.ck
    ).map_err(ZeroArgumentError::CommitmentError)?;
    let verif_upper_a = prod_c_a == comm_a;

    let prod_c_b = [argument.c_upper_b_m.clone()]
        .iter()
        .chain(statement.cs_upper_b.iter().rev())
        .enumerate()
        .map(|(i, c)| c.mod_exponentiate(&x_powers[i], p))
        .fold(MPInteger::one().clone(), |acc, v| acc.mod_multiply(&v, p));
    let comm_b = get_commitment(
        &context.ep,
        &argument.bs_prime,
        &argument.s_prime,
        &context.ck
    ).map_err(ZeroArgumentError::CommitmentError)?;
    let verif_upper_b = prod_c_b == comm_b;

    let prod_c_d = argument.cs_d
        .iter()
        .enumerate()
        .map(|(i, c)| c.mod_exponentiate(&x.mod_exponentiate(&MPInteger::from(i), q), p))
        .fold(MPInteger::one().clone(), |acc, v| acc.mod_multiply(&v, p));
    let prod = star_map(q, &statement.y, &argument.as_prime, &argument.bs_prime).map_err(
        ZeroArgumentError::StarMapError
    )?;
    let comm_d = get_commitment(&context.ep, &[prod], &argument.t_prime, &context.ck).map_err(
        ZeroArgumentError::CommitmentError
    )?;
    let verif_upper_d = prod_c_d == comm_d;

    Ok(ZeroArgumentResult { verif_upper_a, verif_upper_b, verif_upper_d, verif_upper_c_d })
}

fn get_x(
    context: &ArgumentContext,
    statement: &ZeroStatement,
    argument: &ZeroArgument
) -> Result<MPInteger, ZeroArgumentError> {
    Ok(
        HashableMessage::from(
            vec![
                HashableMessage::from(context.ep.p()),
                HashableMessage::from(context.ep.q()),
                HashableMessage::from(context.pks),
                HashableMessage::from(context.ck),
                HashableMessage::from(argument.c_upper_a_0),
                HashableMessage::from(argument.c_upper_b_m),
                HashableMessage::from(argument.cs_d),
                HashableMessage::from(statement.cs_upper_b),
                HashableMessage::from(statement.cs_upper_a)
            ]
        )
            .recursive_hash()
            .map_err(ZeroArgumentError::HashError)?
            .into_mp_integer()
    )
}

impl MixNetResultTrait for ZeroArgumentResult {
    fn is_ok(&self) -> bool {
        self.verif_upper_a && self.verif_upper_b && self.verif_upper_d && self.verif_upper_c_d
    }
}

impl Display for ZeroArgumentResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_ok() {
            return write!(f, "verification ok");
        }
        write!(
            f,
            "verifA: {}, verifB: {}, verifD: {}, verifCd: {}",
            self.verif_upper_a,
            self.verif_upper_b,
            self.verif_upper_d,
            self.verif_upper_c_d
        )
    }
}

impl<'a> ZeroStatement<'a> {
    /// New statement cloning the data
    ///
    /// Return error if the domain is wrong
    pub fn new(
        cs_upper_a: &'a [MPInteger],
        cs_upper_b: &'a [MPInteger],
        y: &'a MPInteger
    ) -> Result<Self, ZeroArgumentError> {
        if cs_upper_a.len() != cs_upper_b.len() {
            return Err(ZeroArgumentError::CommitmentVectorNotSameLen);
        }
        Ok(Self { cs_upper_a, cs_upper_b, y })
    }

    pub fn m(&self) -> usize {
        self.cs_upper_a.len()
    }
}

#[allow(clippy::too_many_arguments)]
impl<'a> ZeroArgument<'a> {
    /// New statement cloning the data
    ///
    /// Return error if the domain is wrong
    pub fn new(
        c_upper_a_0: &'a MPInteger,
        c_upper_b_m: &'a MPInteger,
        cs_d: &'a [MPInteger],
        as_prime: &'a [MPInteger],
        bs_prime: &'a [MPInteger],
        r_prime: &'a MPInteger,
        s_prime: &'a MPInteger,
        t_prime: &'a MPInteger
    ) -> Result<Self, ZeroArgumentError> {
        if as_prime.len() != bs_prime.len() {
            return Err(ZeroArgumentError::ExponentVectorNotSameLen);
        }
        Ok(Self {
            c_upper_a_0,
            c_upper_b_m,
            cs_d,
            as_prime,
            bs_prime,
            r_prime,
            s_prime,
            t_prime,
        })
    }

    pub fn n(&self) -> usize {
        self.as_prime.len()
    }
}

impl<'a, 'b> ZeroArgumentVerifyInput<'a, 'b> {
    /// New Input
    ///
    /// Return error if the domain is wrong
    pub fn new(
        statement: &'a ZeroStatement,
        argument: &'b ZeroArgument
    ) -> Result<Self, ZeroArgumentError> {
        if argument.cs_d.len() != 2 * statement.m() + 1 {
            return Err(ZeroArgumentError::ExponentVectorNotSameLen);
        }
        Ok(Self { statement, argument })
    }
}

#[cfg(test)]
pub mod test {
    use std::path::Path;
    use super::*;
    use serde_json::Value;
    use super::super::test::{
        context_from_json_value,
        context_values,
        ep_from_json_value,
        ck_from_json_value,
    };
    use crate::test_json_data::{ json_array_value_to_array_mpinteger, json_value_to_mpinteger };

    pub struct ZeroStatementValues(pub Vec<MPInteger>, pub Vec<MPInteger>, pub MPInteger);

    pub struct ZeroArgumentValues(
        pub MPInteger,
        pub MPInteger,
        pub Vec<MPInteger>,
        pub Vec<MPInteger>,
        pub Vec<MPInteger>,
        pub MPInteger,
        pub MPInteger,
        pub MPInteger,
    );

    fn get_test_cases() -> Vec<Value> {
        let test_file = Path::new("./")
            .join("test_data")
            .join("mixnet")
            .join("verify-zero-argument.json");
        let json = std::fs::read_to_string(test_file).unwrap();
        serde_json::from_str(&json).unwrap()
    }

    fn get_statement_values(statement: &Value) -> ZeroStatementValues {
        ZeroStatementValues(
            json_array_value_to_array_mpinteger(&statement["c_a"]),
            json_array_value_to_array_mpinteger(&statement["c_b"]),
            json_value_to_mpinteger(&statement["y"])
        )
    }

    fn get_statement<'a>(values: &'a ZeroStatementValues) -> ZeroStatement<'a> {
        ZeroStatement::new(&values.0, &values.1, &values.2).unwrap()
    }

    pub fn get_argument_values(argument: &Value) -> ZeroArgumentValues {
        ZeroArgumentValues(
            json_value_to_mpinteger(&argument["c_a0"]),
            json_value_to_mpinteger(&argument["c_bm"]),
            json_array_value_to_array_mpinteger(&argument["c_d"]),
            json_array_value_to_array_mpinteger(&argument["a"]),
            json_array_value_to_array_mpinteger(&argument["b"]),
            json_value_to_mpinteger(&argument["r"]),
            json_value_to_mpinteger(&argument["s"]),
            json_value_to_mpinteger(&argument["t"])
        )
    }

    pub fn get_argument<'a>(values: &'a ZeroArgumentValues) -> ZeroArgument<'a> {
        ZeroArgument::new(
            &values.0,
            &values.1,
            &values.2,
            &values.3,
            &values.4,
            &values.5,
            &values.6,
            &values.7
        ).unwrap()
    }

    #[test]
    fn test_get_x() {
        for tc in get_test_cases().iter() {
            let context_values = context_values(&tc["context"]);
            let ep = ep_from_json_value(&context_values.0);
            let ck = ck_from_json_value(&context_values.2);
            let context = context_from_json_value(&context_values, &ep, &ck);
            let statement_values = get_statement_values(&tc["input"]["statement"]);
            let statement = get_statement(&statement_values);
            let argument_values = get_argument_values(&tc["input"]["argument"]);
            let argument = get_argument(&argument_values);
            let x_res = get_x(&context, &statement, &argument);
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
            let context_values = context_values(&tc["context"]);
            let ep = ep_from_json_value(&context_values.0);
            let ck = ck_from_json_value(&context_values.2);
            let context = context_from_json_value(&context_values, &ep, &ck);
            let statement_values = get_statement_values(&tc["input"]["statement"]);
            let statement = get_statement(&statement_values);
            let argument_values = get_argument_values(&tc["input"]["argument"]);
            let argument = get_argument(&argument_values);
            let input = ZeroArgumentVerifyInput::new(&statement, &argument).unwrap();
            let x_res = verify_zero_argument(&context, &input);
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
