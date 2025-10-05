// Copyright © 2023 Denis Morel
//
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
// <https://www.gnu.org/licenses/>

use std::fmt::Display;

use thiserror::Error;

use super::{
    ArgumentContext,
    hadamard_argument::{
        HadamardArgument, HadamardArgumentError, HadamardArgumentResult,
        HadamardArgumentVerifyInput, HadamardStatement, verify_hadamard_argument,
    },
    single_value_product_argument::{
        SingleValueProductArgument, SingleValueProductArgumentError,
        SingleValueProductArgumentResult, SingleValueProductStatement,
        SingleValueProductVerifyInput, verify_single_value_product_argument,
    },
};
use crate::{
    Integer,
    mix_net::{MixNetResultTrait, MixnetError, MixnetErrorRepr},
};

/// Statement in input of the verify algorithm
#[derive(Debug, Clone)]
pub struct ProductStatement<'a> {
    cs_upper_a: &'a [Integer],
    b: &'a Integer,
}

/// Argument in input of the verify algorithm
#[derive(Debug, Clone)]
pub struct ProductArgument<'a> {
    c_b: Option<&'a Integer>,
    hadamard_arg: Option<HadamardArgument<'a>>,
    single_value_product_arg: SingleValueProductArgument<'a>,
}

/// Input of the verify algorithm
#[derive(Debug, Clone)]
pub struct ProductArgumentVerifyInput<'a, 'b> {
    statement: &'a ProductStatement<'a>,
    argument: &'b ProductArgument<'b>,
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
    #[error("Error creating Hadamard statement")]
    HadamardStatement { source: HadamardArgumentError },
    #[error("Error creating inputs for Hadamard arguemnt")]
    HadamardArgumentInput { source: HadamardArgumentError },
    #[error("Error verifying Hadamard arguemnt")]
    HadamardArgumentVerification { source: HadamardArgumentError },
    #[error("Error creating single value statement")]
    SVPStatement {
        source: SingleValueProductArgumentError,
    },
    #[error("Error creating inputs for single value arguemnt")]
    SVPArgumentInput {
        source: SingleValueProductArgumentError,
    },
    #[error("Error verifying single value arguemnt")]
    SVPArgumentVerification {
        source: SingleValueProductArgumentError,
    },
}

pub fn verify_product_argument(
    context: &ArgumentContext,
    input: &ProductArgumentVerifyInput,
) -> Result<ProductArgumentResult, ProductArgumentError> {
    let statement = input.statement;
    let argument = input.argument;

    if statement.m() > 1 {
        let c_b = &argument.c_b.as_ref().unwrap();
        let h_statement = HadamardStatement::new(statement.cs_upper_a, c_b)
            .map_err(|e| ProductArgumentError::HadamardStatement { source: e })?;
        let s_statement = SingleValueProductStatement::new(c_b, statement.b)
            .map_err(|e| ProductArgumentError::SVPStatement { source: e })?;
        Ok(ProductArgumentResult {
            hadamard_arg: Some(
                verify_hadamard_argument(
                    context,
                    &HadamardArgumentVerifyInput::new(
                        &h_statement,
                        argument.hadamard_arg.as_ref().unwrap(),
                    )
                    .map_err(|e| ProductArgumentError::HadamardArgumentInput { source: e })?,
                )
                .map_err(|e| ProductArgumentError::HadamardArgumentVerification { source: e })?,
            ),
            single_value_product_arg: verify_single_value_product_argument(
                context,
                &SingleValueProductVerifyInput::new(
                    &s_statement,
                    &argument.single_value_product_arg,
                )
                .map_err(|e| ProductArgumentError::SVPArgumentInput { source: e })?,
            )
            .map_err(|e| ProductArgumentError::SVPArgumentVerification { source: e })?,
        })
    } else {
        let s_statement = SingleValueProductStatement::new(&statement.cs_upper_a[0], statement.b)
            .map_err(|e| ProductArgumentError::SVPStatement { source: e })?;
        Ok(ProductArgumentResult {
            hadamard_arg: None,
            single_value_product_arg: verify_single_value_product_argument(
                context,
                &SingleValueProductVerifyInput::new(
                    &s_statement,
                    &argument.single_value_product_arg,
                )
                .map_err(|e| ProductArgumentError::SVPArgumentInput { source: e })?,
            )
            .map_err(|e| ProductArgumentError::SVPArgumentVerification { source: e })?,
        })
    }
}

impl MixNetResultTrait for ProductArgumentResult {
    fn is_ok(&self) -> bool {
        self.single_value_product_arg.is_ok()
            && (match &self.hadamard_arg {
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
            Some(r) => write!(f, "{svp_str}, Hadamard Argument: {{ {r} }}"),
            None => write!(f, "{svp_str}"),
        }
    }
}

impl<'a> ProductStatement<'a> {
    /// New statement cloning the data
    ///
    /// Return error if the domain is wrong
    pub fn new(cs_upper_a: &'a [Integer], b: &'a Integer) -> Result<Self, ProductArgumentError> {
        Ok(Self { cs_upper_a, b })
    }

    pub fn m(&self) -> usize {
        self.cs_upper_a.len()
    }
}

impl<'a> ProductArgument<'a> {
    /// New statement cloning the data
    ///
    /// Return error if the domain is wrong
    pub fn new(
        c_b: Option<&'a Integer>,
        hadamard_arg: Option<HadamardArgument<'a>>,
        single_value_product_arg: SingleValueProductArgument<'a>,
    ) -> Result<Self, MixnetError> {
        Self::new_impl(c_b, hadamard_arg, single_value_product_arg)
            .map_err(MixnetErrorRepr::from)
            .map_err(|e| MixnetError {
                source: Box::new(e),
            })
    }

    fn new_impl(
        c_b: Option<&'a Integer>,
        hadamard_arg: Option<HadamardArgument<'a>>,
        single_value_product_arg: SingleValueProductArgument<'a>,
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

impl<'a, 'b> ProductArgumentVerifyInput<'a, 'b> {
    /// New Input
    ///
    /// Return error if the domain is wrong
    pub fn new(
        context: &ArgumentContext,
        statement: &'a ProductStatement<'a>,
        argument: &'b ProductArgument<'b>,
    ) -> Result<Self, ProductArgumentError> {
        if statement.m() != argument.m() {
            return Err(ProductArgumentError::MInStatementAndArguemntNotSame);
        }
        if statement.m() == 0 {
            return Err(ProductArgumentError::MNotPositive);
        }
        if let Some(h_arg) = &argument.hadamard_arg
            && (h_arg.n() < 2 || h_arg.n() > context.ck.nu())
        {
            return Err(ProductArgumentError::NNotCorrect);
        }
        Ok(Self {
            statement,
            argument,
        })
    }
}

#[cfg(test)]
pub mod test {
    use super::super::{
        hadamard_argument::test::HadamardArgumentValues,
        hadamard_argument::test::{
            get_argument as get_hadamard_argument,
            get_argument_values as get_hadamard_argument_values,
        },
        single_value_product_argument::test::SVPArgumentValues,
        single_value_product_argument::test::{
            get_argument as get_single_vpa_argument,
            get_argument_values as get_single_vpa_argument_values,
        },
        zero_argument::test::get_argument as get_zero_argument,
    };
    use super::*;
    use crate::mix_net::arguments::test_json_data::json_to_context_values;
    use crate::test_json_data::{
        get_test_cases_from_json_file, json_64_value_to_integer,
        json_array_64_value_to_array_integer,
    };
    use serde_json::Value;

    pub struct ProductStatementValues(pub Vec<Integer>, pub Integer);
    pub struct ProductArgumentValues(
        pub SVPArgumentValues,
        pub Option<HadamardArgumentValues>,
        pub Option<Integer>,
    );

    fn get_statement_values(statement: &Value) -> ProductStatementValues {
        ProductStatementValues(
            json_array_64_value_to_array_integer(&statement["c_a"]),
            json_64_value_to_integer(&statement["b"]),
        )
    }

    fn get_statement(values: &ProductStatementValues) -> ProductStatement<'_> {
        ProductStatement::new(&values.0, &values.1).unwrap()
    }

    pub fn get_argument_values(argument: &Value) -> ProductArgumentValues {
        ProductArgumentValues(
            get_single_vpa_argument_values(&argument["single_vpa"]),
            argument
                .get("hadamard_argument")
                .map(get_hadamard_argument_values),
            argument.get("c_b").map(json_64_value_to_integer),
        )
    }

    pub fn get_argument<'a>(
        values: &'a ProductArgumentValues,
        ha: Option<HadamardArgument<'a>>,
        svp: SingleValueProductArgument<'a>,
    ) -> ProductArgument<'a> {
        ProductArgument::new(values.2.as_ref(), ha, svp).unwrap()
    }

    #[test]
    fn test_verify() {
        for tc in get_test_cases_from_json_file("mixnet", "verify-product-argument.json").iter() {
            let context_values = json_to_context_values(&tc["context"]);
            let context = ArgumentContext::from(&context_values);
            let statement_values = get_statement_values(&tc["input"]["statement"]);
            let statement = get_statement(&statement_values);
            let argument_values = get_argument_values(&tc["input"]["argument"]);
            let svp_argument = get_single_vpa_argument(&argument_values.0);
            let zero_argument = argument_values
                .1
                .as_ref()
                .map(|vs| get_zero_argument(&vs.1));
            let hadamard_argument = argument_values
                .1
                .as_ref()
                .map(|vs| get_hadamard_argument(vs, zero_argument.unwrap()));
            let argument = get_argument(&argument_values, hadamard_argument, svp_argument);
            let input = ProductArgumentVerifyInput::new(&context, &statement, &argument).unwrap();
            let x_res = verify_product_argument(&context, &input);
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
