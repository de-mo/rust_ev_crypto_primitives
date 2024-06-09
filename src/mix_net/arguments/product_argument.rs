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

use std::fmt::Display;

use thiserror::Error;

use crate::{
    integer::MPInteger,
    mix_net::{ commitments::CommitmentError, MixNetResultTrait },
    HashError,
};
use super::{
    hadamard_argument::{
        verify_hadamard_argument,
        HadamardArgument,
        HadamardArgumentError,
        HadamardArgumentResult,
        HadamardArgumentVerifyInput,
        HadamardStatement,
    },
    single_value_product_argument::{
        verify_single_value_product_argument,
        SingleValueProductArgument,
        SingleValueProductArgumentError,
        SingleValueProductArgumentResult,
        SingleValueProductStatement,
        SingleValueProductVerifyInput,
    },
    ArgumentContext,
};

/// Statement in input of the verify algorithm
#[derive(Debug, Clone)]
pub struct ProductStatement {
    cs_upper_a: Vec<MPInteger>,
    b: MPInteger,
}

/// Argument in input of the verify algorithm
#[derive(Debug, Clone)]
pub struct ProductArgument {
    c_b: Option<MPInteger>,
    hadamard_arg: Option<HadamardArgument>,
    single_value_product_arg: SingleValueProductArgument,
}

/// Input of the verify algorithm
#[derive(Debug, Clone)]
pub struct ProductArgumentVerifyInput<'a> {
    statement: &'a ProductStatement,
    argument: &'a ProductArgument,
}

/// Result of the verify algorithm, according to the specifications
#[derive(Debug, Eq, PartialEq)]
pub struct ProductArgumentResult {
    hadamard_arg: Option<HadamardArgumentResult>,
    single_value_product_arg: SingleValueProductArgumentResult,
}

/// Error during the process
#[derive(Error, Debug)]
pub enum ProductArgumentError {
    #[error("Hadamard argument and commitment must be both set or not")]
    BothNoneOrSome,
    #[error("Hadamard argument cannot be defined if m=1")]
    HadamardArgumentSetWithMIsOne,
    #[error("m in statement and argument are not the same")]
    MInStatementAndArguemntNotSame,
    #[error("m must be positive")]
    MNotPositive,
    #[error("n must be between 2 and nu")]
    NNotCorrect,
    //#[error("Exponent vectors a' and b' have not the same size")]
    //ExponentVectorNotSameLen,
    //#[error(
    //    "Commitment vector c_d has not the size 2*m + 1 where m={0}"
    //)] CommitmentVectorNotCorrectSize(usize),
    #[error("HashError: {0}")] HashError(#[from] HashError),
    #[error("CommitmentError: {0}")] CommitmentError(#[from] CommitmentError),
    #[error("SingleValueProductArgumentError: {0}")] SingleValueProductArgumentError(
        #[from] SingleValueProductArgumentError,
    ),
    #[error("HadamardArgumentError: {0}")] HadamardArgumentError(#[from] HadamardArgumentError),
}

pub fn verify_product_argument(
    context: &ArgumentContext,
    input: &ProductArgumentVerifyInput
) -> Result<ProductArgumentResult, ProductArgumentError> {
    let statement = input.statement;
    let argument = input.argument;

    if statement.m() > 1 {
        let c_b = &argument.c_b.as_ref().unwrap();
        let h_statement = HadamardStatement::new(&statement.cs_upper_a, c_b).map_err(
            ProductArgumentError::HadamardArgumentError
        )?;
        let s_statement = SingleValueProductStatement::new(c_b, &statement.b).map_err(
            ProductArgumentError::SingleValueProductArgumentError
        )?;
        Ok(ProductArgumentResult {
            hadamard_arg: Some(
                verify_hadamard_argument(
                    context,
                    &HadamardArgumentVerifyInput::new(
                        &h_statement,
                        argument.hadamard_arg.as_ref().unwrap()
                    ).map_err(ProductArgumentError::HadamardArgumentError)?
                ).map_err(ProductArgumentError::HadamardArgumentError)?
            ),
            single_value_product_arg: verify_single_value_product_argument(
                context,
                &SingleValueProductVerifyInput::new(
                    &s_statement,
                    &argument.single_value_product_arg
                ).map_err(ProductArgumentError::SingleValueProductArgumentError)?
            ).map_err(ProductArgumentError::SingleValueProductArgumentError)?,
        })
    } else {
        let s_statement = SingleValueProductStatement::new(
            &statement.cs_upper_a[0],
            &statement.b
        ).map_err(ProductArgumentError::SingleValueProductArgumentError)?;
        Ok(ProductArgumentResult {
            hadamard_arg: None,
            single_value_product_arg: verify_single_value_product_argument(
                context,
                &SingleValueProductVerifyInput::new(
                    &s_statement,
                    &argument.single_value_product_arg
                ).map_err(ProductArgumentError::SingleValueProductArgumentError)?
            ).map_err(ProductArgumentError::SingleValueProductArgumentError)?,
        })
    }
}

impl MixNetResultTrait for ProductArgumentResult {
    fn is_ok(&self) -> bool {
        self.single_value_product_arg.is_ok() &&
            (match &self.hadamard_arg {
                Some(v) => v.is_ok(),
                None => true,
            })
    }
}

impl Display for ProductArgumentResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_ok() {
            return write!(f, "verification ok");
        }
        let svp_str = format!(
            "Single Value Product Argument: {{ {} }}",
            self.single_value_product_arg
        );
        match &self.hadamard_arg {
            Some(r) => write!(f, "{}, Hadamard Argument: {{ {} }}", svp_str, r),
            None => write!(f, "{}", svp_str),
        }
    }
}

impl ProductStatement {
    /// New statement taking the ownership of the data
    ///
    /// Return error if the domain is wrong
    pub fn new_owned(
        cs_upper_a: Vec<MPInteger>,
        b: MPInteger
    ) -> Result<Self, ProductArgumentError> {
        Ok(Self { cs_upper_a, b })
    }

    /// New statement cloning the data
    ///
    /// Return error if the domain is wrong
    pub fn new(cs_upper_a: &[MPInteger], b: &MPInteger) -> Result<Self, ProductArgumentError> {
        Self::new_owned(cs_upper_a.to_vec(), b.clone())
    }

    pub fn m(&self) -> usize {
        self.cs_upper_a.len()
    }
}

impl ProductArgument {
    /// New statement taking the ownership of the data
    ///
    /// Return error if the domain is wrong
    pub fn new_owned(
        c_b: Option<MPInteger>,
        hadamard_arg: Option<HadamardArgument>,
        single_value_product_arg: SingleValueProductArgument
    ) -> Result<Self, ProductArgumentError> {
        if (c_b.is_some() && hadamard_arg.is_none()) || (c_b.is_none() && hadamard_arg.is_some()) {
            return Err(ProductArgumentError::BothNoneOrSome);
        }
        if hadamard_arg.is_some() && hadamard_arg.as_ref().unwrap().m() == 1 {
            return Err(ProductArgumentError::HadamardArgumentSetWithMIsOne);
        }
        Ok(Self {
            c_b,
            hadamard_arg,
            single_value_product_arg,
        })
    }

    /// New statement cloning the data
    ///
    /// Return error if the domain is wrong
    pub fn new(
        c_b: Option<&MPInteger>,
        hadamard_arg: Option<&HadamardArgument>,
        single_value_product_arg: &SingleValueProductArgument
    ) -> Result<Self, ProductArgumentError> {
        Self::new_owned(c_b.cloned(), hadamard_arg.cloned(), single_value_product_arg.clone())
    }

    pub fn m(&self) -> usize {
        match &self.hadamard_arg {
            Some(h) => h.m(),
            None => 1,
        }
    }

    pub fn n(&self) -> Option<usize> {
        self.hadamard_arg.as_ref().map(|h| h.n())
    }
}

impl<'a> ProductArgumentVerifyInput<'a> {
    /// New Input
    ///
    /// Return error if the domain is wrong
    pub fn new(
        context: &ArgumentContext,
        statement: &'a ProductStatement,
        argument: &'a ProductArgument
    ) -> Result<Self, ProductArgumentError> {
        if statement.m() != argument.m() {
            return Err(ProductArgumentError::MInStatementAndArguemntNotSame);
        }
        if statement.m() == 0 {
            return Err(ProductArgumentError::MNotPositive);
        }
        if let Some(h_arg) = &argument.hadamard_arg {
            if h_arg.n() < 2 || h_arg.n() > context.ck.nu() {
                return Err(ProductArgumentError::NNotCorrect);
            }
        }
        Ok(Self { statement, argument })
    }
}

#[cfg(test)]
pub mod test {
    use std::path::Path;
    use super::*;
    use serde_json::Value;
    use super::super::{
        single_value_product_argument::test::get_argument as get_single_vpa_argument,
        hadamard_argument::test::get_argument as get_hadamard_argument,
        test::context_from_json_value,
    };
    use crate::test_json_data::{ json_array_value_to_array_mpinteger, json_value_to_mpinteger };

    fn get_test_cases() -> Vec<Value> {
        let test_file = Path::new("./")
            .join("test_data")
            .join("mixnet")
            .join("verify-product-argument.json");
        let json = std::fs::read_to_string(test_file).unwrap();
        serde_json::from_str(&json).unwrap()
    }

    fn get_context(tc: &Value) -> ArgumentContext {
        context_from_json_value(&tc["context"])
    }

    fn get_statement(statement: &Value) -> ProductStatement {
        ProductStatement::new(
            &json_array_value_to_array_mpinteger(&statement["c_a"]),
            &json_value_to_mpinteger(&statement["b"])
        ).unwrap()
    }

    pub fn get_argument(argument: &Value) -> ProductArgument {
        let single_vpa = get_single_vpa_argument(&argument["single_vpa"]);
        let hadamard_argument = argument.get("hadamard_argument").map(get_hadamard_argument);
        let c_b = argument.get("c_b").map(json_value_to_mpinteger);
        ProductArgument::new(c_b.as_ref(), hadamard_argument.as_ref(), &single_vpa).unwrap()
    }

    #[test]
    fn test_verify() {
        for tc in get_test_cases().iter() {
            let context = get_context(tc);
            let statement = get_statement(&tc["input"]["statement"]);
            let argument = get_argument(&tc["input"]["argument"]);
            let input = ProductArgumentVerifyInput::new(&context, &statement, &argument).unwrap();
            let x_res = verify_product_argument(&context, &input);
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
