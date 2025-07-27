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

use super::{
    multi_exponentiation_argument::{
        verify_multi_exponentiation_argument, MultiExponentiationArgument,
        MultiExponentiationArgumentError, MultiExponentiationArgumentResult,
        MultiExponentiationArgumentVerifyInput, MultiExponentiationStatement,
    },
    product_argument::{ProductArgument, ProductArgumentError, ProductArgumentResult},
    ArgumentContext,
};
use crate::{
    elgamal::{Ciphertext, ElgamalError},
    integer::ModExponentiateError,
    mix_net::{
        arguments::product_argument::{
            verify_product_argument, ProductArgumentVerifyInput, ProductStatement,
        },
        commitments::{get_commitment_matrix, CommitmentError},
        matrix::{Matrix, MatrixError},
        MixNetResultTrait, MixnetError, MixnetErrorRepr,
    },
    ConstantsTrait, HashError, HashableMessage, Integer, OperationsTrait, RecursiveHashTrait,
};
use std::fmt::Display;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct ShuffleStatement<'a> {
    upper_cs: &'a [Ciphertext],
    upper_c_primes: &'a [Ciphertext],
}

/// Shuffle argument according to the speicifcation of Swiss Post
#[derive(Debug, Clone)]
pub struct ShuffleArgument<'a> {
    cs_upper_a: &'a [Integer],
    cs_upper_b: &'a [Integer],
    product_argument: ProductArgument<'a>,
    multi_exponentiation_argument: MultiExponentiationArgument<'a>,
}

/// Input of the verify algorithm
#[derive(Debug, Clone)]
pub struct ShuffleArgumentVerifyInput<'a, 'b> {
    statement: &'a ShuffleStatement<'a>,
    argument: &'b ShuffleArgument<'b>,
}

#[derive(Debug)]
pub struct VerifyShuffleArgumentResult {
    pub product_verif: ProductArgumentResult,
    pub multi_verif: MultiExponentiationArgumentResult,
}

#[derive(Error, Debug)]
pub enum ShuffleArgumentError {
    #[error("Inconsistent lenght of list of cyphertexts")]
    LengthListCypherTextInconsistent,
    #[error("Inconsistent lenght of list of cyphertexts")]
    LengthCypherTextInconsistent,
    #[error("n must be greater or equal 2 and less or equal nu={1}. It is {0}")]
    SmallNWorng(usize, usize),
    #[error("m is not consistent in {0}")]
    MNotConsistent(String),
    #[error("n is not consistent in {0}")]
    NNotConsistent(String),
    #[error("N ist not n*m")]
    NNotProductOfNAndM,
    #[error("l must be bigger than 0 and less or equal k")]
    LNotInRange,
    #[error("Error for x")]
    X { source: HashError },
    #[error("Error for y")]
    Y { source: HashError },
    #[error("Error for z")]
    Z { source: HashError },
    #[error("Error creating matrix upper_z_neg")]
    UZNeg { source: MatrixError },
    #[error("Error transposing matrix upper_z_neg")]
    UZNegTranspose { source: MatrixError },
    #[error("Error calculating c_(-z)")]
    CSMinusZ { source: CommitmentError },
    #[error("Error calculating c_D")]
    CUppderD { source: ModExponentiateError },
    #[error("Error calculating vector x")]
    XS { source: ModExponentiateError },
    #[error("Error calculating ciphertext C")]
    UpperC { source: ElgamalError },
    #[error("Error calculating matrix of ciphertexts")]
    MatrixC { source: MatrixError },
    #[error("Error calculating product statement")]
    ProdStatement { source: ProductArgumentError },
    #[error("Error calculating input for product argument verification")]
    ProdArgInput { source: ProductArgumentError },
    #[error("Error verifiying product argument")]
    ProdVerification { source: ProductArgumentError },
    #[error("Error calculating multi exponentational statement")]
    MultExpStatement {
        source: MultiExponentiationArgumentError,
    },
    #[error("Error calculating input for multi exponentational argument verification")]
    MultExpArgInput {
        source: MultiExponentiationArgumentError,
    },
    #[error("Error verifiying multi exponentational argument")]
    MultExpVerification {
        source: MultiExponentiationArgumentError,
    },
}

pub fn verify_shuffle_argument(
    context: &ArgumentContext,
    input: &ShuffleArgumentVerifyInput,
) -> Result<VerifyShuffleArgumentResult, ShuffleArgumentError> {
    let statement = input.statement;
    let argument = input.argument;
    let upper_n = statement.upper_n();
    let m = argument.m();
    let n = argument.n();
    let p = context.ep.p();
    let q = context.ep.q();

    let x =
        get_x(context, statement, argument).map_err(|e| ShuffleArgumentError::X { source: e })?;
    let y =
        get_y(context, statement, argument).map_err(|e| ShuffleArgumentError::Y { source: e })?;
    let z =
        get_z(context, statement, argument).map_err(|e| ShuffleArgumentError::Z { source: e })?;

    let upper_z_neg = Matrix::to_matrix(&vec![z.mod_negate(q); upper_n], (m, n))
        .map_err(|e| ShuffleArgumentError::UZNeg { source: e })?
        .transpose()
        .map_err(|e| ShuffleArgumentError::UZNegTranspose { source: e })?;

    let cs_minus_z = get_commitment_matrix(
        context.ep,
        &upper_z_neg,
        &vec![Integer::zero().clone(); m],
        context.ck,
    )
    .map_err(|e| ShuffleArgumentError::CSMinusZ { source: e })?;

    let cs_upper_d = argument
        .cs_upper_a
        .iter()
        .zip(argument.cs_upper_b.iter())
        .map(|(c_a_i, c_b_i)| {
            c_a_i
                .mod_exponentiate(&y, p)
                .map(|v| v.mod_multiply(c_b_i, p))
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ShuffleArgumentError::CUppderD { source: e })?;
    /*argument
    .cs_upper_a
    .iter()
    .zip(argument.cs_upper_b.iter())
    .map(|(c_a_i, c_b_i)| c_a_i.mod_exponentiate(&y, p).mod_multiply(c_b_i, p))
    .collect();*/

    let xs = (0..upper_n)
        .map(|i| x.mod_exponentiate(&Integer::from(i), q))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ShuffleArgumentError::XS { source: e })?;

    let b = xs
        .iter()
        .enumerate()
        .take(upper_n)
        //.skip(1)
        .map(|(i, x_i)| {
            y.mod_multiply(&Integer::from(i), q)
                .mod_add(x_i, q)
                .mod_sub(&z, q)
        })
        .fold(Integer::one().clone(), |acc, v| acc.mod_multiply(&v, q));

    let p_statement_value = cs_upper_d
        .iter()
        .zip(cs_minus_z.iter())
        .map(|(c_d_i, c_z_i)| c_d_i.mod_multiply(c_z_i, p))
        .collect::<Vec<_>>();
    let p_statement = ProductStatement::new(p_statement_value.as_slice(), &b)
        .map_err(|e| ShuffleArgumentError::ProdStatement { source: e })?;
    let product_verif = verify_product_argument(
        context,
        &ProductArgumentVerifyInput::new(context, &p_statement, &argument.product_argument)
            .map_err(|e| ShuffleArgumentError::ProdArgInput { source: e })?,
    )
    .map_err(|e| ShuffleArgumentError::ProdVerification { source: e })?;

    let upper_c =
        Ciphertext::get_ciphertext_vector_exponentiation(statement.upper_cs, &xs, context.ep)
            .map_err(|e| ShuffleArgumentError::UpperC { source: e })?;
    let cipher_matrix = Matrix::to_matrix(statement.upper_c_primes, (m, n))
        .map_err(|e| ShuffleArgumentError::MatrixC { source: e })?;
    let m_statement =
        MultiExponentiationStatement::new(&cipher_matrix, &upper_c, argument.cs_upper_b)
            .map_err(|e| ShuffleArgumentError::MultExpStatement { source: e })?;
    let multi_verif = verify_multi_exponentiation_argument(
        context,
        &MultiExponentiationArgumentVerifyInput::new(
            &m_statement,
            &argument.multi_exponentiation_argument,
        )
        .map_err(|e| ShuffleArgumentError::MultExpArgInput { source: e })?,
    )
    .map_err(|e| ShuffleArgumentError::MultExpVerification { source: e })?;

    Ok(VerifyShuffleArgumentResult {
        product_verif,
        multi_verif,
    })
}

pub fn get_x(
    context: &ArgumentContext,
    statement: &ShuffleStatement,
    argument: &ShuffleArgument,
) -> Result<Integer, HashError> {
    Ok(
        HashableMessage::from(get_hashable_vector_for_x(context, statement, argument))
            .recursive_hash()?
            .into_integer(),
    )
}

pub fn get_y(
    context: &ArgumentContext,
    statement: &ShuffleStatement,
    argument: &ShuffleArgument,
) -> Result<Integer, HashError> {
    Ok(
        HashableMessage::from(get_hashable_vector_for_y(context, statement, argument))
            .recursive_hash()?
            .into_integer(),
    )
}

pub fn get_z(
    context: &ArgumentContext,
    statement: &ShuffleStatement,
    argument: &ShuffleArgument,
) -> Result<Integer, HashError> {
    Ok(
        HashableMessage::from(get_hashable_vector_for_z(context, statement, argument))
            .recursive_hash()?
            .into_integer(),
    )
}

fn get_hashable_vector_for_x<'a>(
    context: &'a ArgumentContext,
    statement: &'a ShuffleStatement,
    argument: &'a ShuffleArgument,
) -> Vec<HashableMessage<'a>> {
    vec![
        HashableMessage::from(context.ep.p()),
        HashableMessage::from(context.ep.q()),
        HashableMessage::from(context.pks),
        HashableMessage::from(context.ck),
        HashableMessage::from(statement.upper_cs),
        HashableMessage::from(statement.upper_c_primes),
        HashableMessage::from(
            argument
                .cs_upper_a
                .iter()
                .map(HashableMessage::from)
                .collect::<Vec<_>>(),
        ),
    ]
}

fn get_hashable_vector_for_y<'a>(
    context: &'a ArgumentContext,
    statement: &'a ShuffleStatement,
    argument: &'a ShuffleArgument,
) -> Vec<HashableMessage<'a>> {
    let mut res = get_hashable_vector_for_x(context, statement, argument);
    res.insert(
        0,
        HashableMessage::from(
            argument
                .cs_upper_b
                .iter()
                .map(HashableMessage::from)
                .collect::<Vec<HashableMessage>>(),
        ),
    );
    res
}

fn get_hashable_vector_for_z<'a>(
    context: &'a ArgumentContext,
    statement: &'a ShuffleStatement,
    argument: &'a ShuffleArgument,
) -> Vec<HashableMessage<'a>> {
    let mut res = get_hashable_vector_for_y(context, statement, argument);
    res.insert(0, HashableMessage::from("1"));
    res
}

impl MixNetResultTrait for VerifyShuffleArgumentResult {
    fn is_ok(&self) -> bool {
        self.multi_verif.is_ok() && self.product_verif.is_ok()
    }
}

impl Display for VerifyShuffleArgumentResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "productVerif: {{ {} }} / multiVerif: {{ {} }}",
            self.product_verif, self.multi_verif
        )
    }
}

impl<'a> ShuffleStatement<'a> {
    /// New statement cloning the data
    ///
    /// Return error if the domain is wrong
    pub fn new(
        upper_cs: &'a [Ciphertext],
        upper_c_primes: &'a [Ciphertext],
    ) -> Result<Self, ShuffleArgumentError> {
        let upper_n = upper_cs.len();
        if upper_c_primes.len() != upper_n {
            return Err(ShuffleArgumentError::LengthListCypherTextInconsistent);
        }
        let l = upper_cs[0].l();
        if upper_cs.iter().any(|c| c.l() != l) || upper_c_primes.iter().any(|c| c.l() != l) {
            return Err(ShuffleArgumentError::LengthCypherTextInconsistent);
        }
        Ok(Self {
            upper_cs,
            upper_c_primes,
        })
    }

    pub fn l(&self) -> usize {
        self.upper_cs[0].l()
    }

    pub fn upper_n(&self) -> usize {
        self.upper_cs.len()
    }
}

impl<'a> ShuffleArgument<'a> {
    /// New statement cloning the data
    ///
    /// Return error if the domain is wrong
    pub fn new(
        cs_upper_a: &'a [Integer],
        cs_upper_b: &'a [Integer],
        product_argument: ProductArgument<'a>,
        multi_exponentiation_argument: MultiExponentiationArgument<'a>,
    ) -> Result<Self, MixnetError> {
        Self::new_impl(
            cs_upper_a,
            cs_upper_b,
            product_argument,
            multi_exponentiation_argument,
        )
        .map_err(MixnetErrorRepr::from)
        .map_err(|e| MixnetError {
            source: Box::new(e),
        })
    }

    fn new_impl(
        cs_upper_a: &'a [Integer],
        cs_upper_b: &'a [Integer],
        product_argument: ProductArgument<'a>,
        multi_exponentiation_argument: MultiExponentiationArgument<'a>,
    ) -> Result<Self, ShuffleArgumentError> {
        let m = cs_upper_a.len();
        let n = multi_exponentiation_argument.n();
        if cs_upper_b.len() != m {
            return Err(ShuffleArgumentError::MNotConsistent("c_B".to_string()));
        }
        if multi_exponentiation_argument.m() != m {
            return Err(ShuffleArgumentError::MNotConsistent(
                "multiExponentiationArgument".to_string(),
            ));
        }
        if product_argument.m() != m {
            return Err(ShuffleArgumentError::MNotConsistent(
                "ProductArgmuent".to_string(),
            ));
        }
        if let Some(p_n) = product_argument.n() {
            if p_n != n {
                return Err(ShuffleArgumentError::NNotConsistent(
                    "ProductArgmuent".to_string(),
                ));
            }
        }
        Ok(Self {
            cs_upper_a,
            cs_upper_b,
            product_argument,
            multi_exponentiation_argument,
        })
    }

    pub fn m(&self) -> usize {
        self.cs_upper_a.len()
    }

    pub fn n(&self) -> usize {
        self.multi_exponentiation_argument.n()
    }
}

impl<'a, 'b> ShuffleArgumentVerifyInput<'a, 'b> {
    /// New Input
    ///
    /// Return error if the domain is wrong
    pub fn new(
        context: &ArgumentContext,
        statement: &'a ShuffleStatement<'a>,
        argument: &'b ShuffleArgument<'b>,
    ) -> Result<Self, ShuffleArgumentError> {
        if statement.upper_n() != argument.m() * argument.n() {
            return Err(ShuffleArgumentError::NNotProductOfNAndM);
        }
        if statement.l() == 0 && statement.l() > context.pks.len() {
            return Err(ShuffleArgumentError::LNotInRange);
        }
        if argument.n() < 2 || argument.n() > context.ck.nu() {
            return Err(ShuffleArgumentError::SmallNWorng(
                argument.n(),
                context.ck.nu(),
            ));
        }
        Ok(Self {
            statement,
            argument,
        })
    }
}

#[cfg(test)]
mod test {
    use super::super::test::{
        ck_from_json_value, context_from_json_value, context_values, ep_from_json_value,
    };
    use super::super::{
        hadamard_argument::test::get_argument as get_hadamard_argument,
        multi_exponentiation_argument::test::{
            get_argument as get_me_argument, get_argument_values as get_me_argument_values,
            get_ciphertexts, MEArgumentValues,
        },
        product_argument::test::{
            get_argument as get_product_argument,
            get_argument_values as get_product_argument_values, ProductArgumentValues,
        },
        single_value_product_argument::test::get_argument as get_single_vpa_argument,
        zero_argument::test::get_argument as get_zero_argument,
    };
    use super::*;
    use crate::test_json_data::json_array_exa_value_to_array_integer;
    use serde_json::Value;
    use std::path::Path;

    fn get_test_cases() -> Vec<Value> {
        let test_file = Path::new("./")
            .join("test_data")
            .join("mixnet")
            .join("verify-shuffle-argument.json");
        let json = std::fs::read_to_string(test_file).unwrap();
        serde_json::from_str(&json).unwrap()
    }

    pub struct ShuffleStatementValues(pub Vec<Ciphertext>, pub Vec<Ciphertext>);
    pub struct ShuffleArgumentValues(
        pub Vec<Integer>,
        pub Vec<Integer>,
        ProductArgumentValues,
        MEArgumentValues,
    );

    fn get_statement_values(statement: &Value) -> ShuffleStatementValues {
        ShuffleStatementValues(
            get_ciphertexts(&statement["ciphertexts"]),
            get_ciphertexts(&statement["shuffled_ciphertexts"]),
        )
    }

    fn get_statement(values: &ShuffleStatementValues) -> ShuffleStatement<'_> {
        ShuffleStatement::new(&values.0, &values.1).unwrap()
    }

    fn get_argument_values(argument: &Value) -> ShuffleArgumentValues {
        ShuffleArgumentValues(
            json_array_exa_value_to_array_integer(&argument["ca"]),
            json_array_exa_value_to_array_integer(&argument["cb"]),
            get_product_argument_values(&argument["product_argument"]),
            get_me_argument_values(&argument["multi_exp_argument"]),
        )
    }

    fn get_argument<'a>(
        values: &'a ShuffleArgumentValues,
        pe: ProductArgument<'a>,
        me: MultiExponentiationArgument<'a>,
    ) -> ShuffleArgument<'a> {
        ShuffleArgument::new(&values.0, &values.1, pe, me).unwrap()
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
            let me_argument = get_me_argument(&argument_values.3);
            let product_argument_values = &argument_values.2;
            let svp_argument = get_single_vpa_argument(&product_argument_values.0);
            let zero_argument = product_argument_values
                .1
                .as_ref()
                .map(|vs| get_zero_argument(&vs.1));
            let hadamard_argument = product_argument_values
                .1
                .as_ref()
                .map(|vs| get_hadamard_argument(vs, zero_argument.unwrap()));
            let product_argument =
                get_product_argument(product_argument_values, hadamard_argument, svp_argument);
            let argument = get_argument(&argument_values, product_argument, me_argument);
            let input = ShuffleArgumentVerifyInput::new(&context, &statement, &argument).unwrap();
            let x_res = verify_shuffle_argument(&context, &input);
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
