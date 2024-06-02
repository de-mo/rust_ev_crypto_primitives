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
    mix_net::{
        arguments::product_argument::{
            verify_product_argument,
            ProductArgumentVerifyInput,
            ProductStatement,
        },
        commitments::{ get_commitment_matrix, CommitmentError },
        matrix::{ Matrix, MatrixError },
        MixNetResultTrait,
    },
    Ciphertext,
    Constants,
    HashError,
    HashableMessage,
    Operations,
    RecursiveHashTrait,
};

use super::{
    multi_exponentiation_argument::{
        verify_multi_exponentiation_argument,
        MultiExponentiationArgument,
        MultiExponentiationArgumentError,
        MultiExponentiationArgumentResult,
        MultiExponentiationArgumentVerifyInput,
        MultiExponentiationStatement,
    },
    product_argument::{ ProductArgument, ProductArgumentError, ProductArgumentResult },
    ArgumentContext,
};

#[derive(Debug, Clone)]
pub struct ShuffleStatement {
    upper_cs: Vec<Ciphertext>,
    upper_c_primes: Vec<Ciphertext>,
}

/// Shuffle argument according to the speicifcation of Swiss Post
#[derive(Debug, Clone)]
pub struct ShuffleArgument {
    cs_upper_a: Vec<MPInteger>,
    cs_upper_b: Vec<MPInteger>,
    product_argument: ProductArgument,
    multi_exponentiation_argument: MultiExponentiationArgument,
}

/// Input of the verify algorithm
#[derive(Debug, Clone)]
pub struct ShuffleArgumentVerifyInput<'a> {
    statement: &'a ShuffleStatement,
    argument: &'a ShuffleArgument,
}

#[derive(Debug)]
pub struct VerifyShuffleArgumentResult {
    pub product_verif: ProductArgumentResult,
    pub multi_verif: MultiExponentiationArgumentResult,
}

#[derive(Error, Debug)]
pub enum ShuffleArgumentError {
    #[error("Inconsistent lenght of list of cyphertexts")] LengthListCypherTextInconsistent,
    #[error("Inconsistent lenght of list of cyphertexts")] LengthCypherTextInconsistent,
    #[error("n must be greater or equal 2 and less or equal nu={1}. It is {0}")] SmallNWorng(
        usize,
        usize,
    ),
    #[error("m is not consistent in {0}")] MNotConsistent(String),
    #[error("n is not consistent in {0}")] NNotConsistent(String),
    #[error("N ist not n*m")] NNotProductOfNAndM,
    #[error("l must be bigger than 0 and less or equal k")] LNotInRange,
    #[error("HashError: {0}")] HashError(#[from] HashError),
    #[error("CommitmentError: {0}")] CommitmentError(#[from] CommitmentError),
    #[error("MatrixError: {0}")] MatrixError(#[from] MatrixError),
    #[error("ProductArgumentError: {0}")] ProductArgumentError(#[from] ProductArgumentError),
    #[error("MultiExponentiationArgumentError: {0}")] MultiExponentiationArgumentError(
        #[from] MultiExponentiationArgumentError,
    ),
}

pub fn verify_shuffle_argument(
    context: &ArgumentContext,
    input: &ShuffleArgumentVerifyInput
) -> Result<VerifyShuffleArgumentResult, ShuffleArgumentError> {
    let statement = input.statement;
    let argument = input.argument;
    let upper_n = statement.upper_n();
    let m = argument.m();
    let n = argument.n();
    let p = context.ep.p();

    let x = get_x(context, statement, argument)?;
    let y = get_y(context, statement, argument)?;
    let z = get_z(context, statement, argument)?;

    let upper_z_neg = Matrix::to_matrix(&vec![-z.clone(); upper_n], (m, n))
        .map_err(ShuffleArgumentError::MatrixError)?
        .transpose()
        .map_err(ShuffleArgumentError::MatrixError)?;

    let cs_minus_z = get_commitment_matrix(
        &context.ep,
        &upper_z_neg,
        &vec![MPInteger::zero().clone(); m],
        &context.ck
    ).map_err(ShuffleArgumentError::CommitmentError)?;

    let cs_upper_d: Vec<MPInteger> = argument.cs_upper_a
        .iter()
        .zip(argument.cs_upper_b.iter())
        .map(|(a, b)| { a.mod_exponentiate(&y, p).mod_multiply(b, p) })
        .collect();

    let b = (1..upper_n + 1)
        .map(|i| &y * i + x.mod_exponentiate(&MPInteger::from(i), p) - &z)
        .fold(MPInteger::one().clone(), |acc, v| { acc.mod_multiply(&v, p) });
    let p_statement = ProductStatement::new(
        &cs_upper_d
            .iter()
            .zip(cs_minus_z.iter())
            .map(|(c_d_i, c_z_i)| c_d_i.mod_multiply(c_z_i, p))
            .collect::<Vec<_>>(),
        &b
    ).map_err(ShuffleArgumentError::ProductArgumentError)?;
    let product_verif = verify_product_argument(
        context,
        &ProductArgumentVerifyInput::new(context, &p_statement, &argument.product_argument).map_err(
            ShuffleArgumentError::ProductArgumentError
        )?
    ).map_err(ShuffleArgumentError::ProductArgumentError)?;

    let xs = (0..upper_n).map(|i| x.mod_exponentiate(&MPInteger::from(i), p)).collect::<Vec<_>>();
    let upper_c = Ciphertext::get_ciphertext_vector_exponentiation(
        &statement.upper_cs,
        &xs,
        &context.ep
    );
    let m_statement = MultiExponentiationStatement::new(
        &Matrix::to_matrix(&statement.upper_c_primes, (m, n)).map_err(
            ShuffleArgumentError::MatrixError
        )?,
        &upper_c,
        &argument.cs_upper_b
    ).map_err(ShuffleArgumentError::MultiExponentiationArgumentError)?;
    let multi_verif = verify_multi_exponentiation_argument(
        context,
        &MultiExponentiationArgumentVerifyInput::new(
            &m_statement,
            &argument.multi_exponentiation_argument
        ).map_err(ShuffleArgumentError::MultiExponentiationArgumentError)?
    ).map_err(ShuffleArgumentError::MultiExponentiationArgumentError)?;

    Ok(VerifyShuffleArgumentResult { product_verif, multi_verif })
}

pub fn get_x(
    context: &ArgumentContext,
    statement: &ShuffleStatement,
    argument: &ShuffleArgument
) -> Result<MPInteger, ShuffleArgumentError> {
    Ok(
        HashableMessage::from(get_hashable_vector_for_x(context, statement, argument))
            .recursive_hash()
            .map_err(ShuffleArgumentError::HashError)?
            .into_mp_integer()
    )
}

pub fn get_y(
    context: &ArgumentContext,
    statement: &ShuffleStatement,
    argument: &ShuffleArgument
) -> Result<MPInteger, ShuffleArgumentError> {
    Ok(
        HashableMessage::from(get_hashable_vector_for_y(context, statement, argument))
            .recursive_hash()
            .map_err(ShuffleArgumentError::HashError)?
            .into_mp_integer()
    )
}

pub fn get_z(
    context: &ArgumentContext,
    statement: &ShuffleStatement,
    argument: &ShuffleArgument
) -> Result<MPInteger, ShuffleArgumentError> {
    Ok(
        HashableMessage::from(get_hashable_vector_for_z(context, statement, argument))
            .recursive_hash()
            .map_err(ShuffleArgumentError::HashError)?
            .into_mp_integer()
    )
}

fn get_hashable_vector_for_x<'a>(
    context: &'a ArgumentContext,
    statement: &'a ShuffleStatement,
    argument: &'a ShuffleArgument
) -> Vec<HashableMessage<'a>> {
    vec![
        HashableMessage::from(context.ep.p()),
        HashableMessage::from(context.ep.q()),
        HashableMessage::from(&context.pks),
        HashableMessage::from(&context.ck),
        HashableMessage::from(
            statement.upper_cs.iter().map(HashableMessage::from).collect::<Vec<HashableMessage>>()
        ),
        HashableMessage::from(
            statement.upper_c_primes
                .iter()
                .map(HashableMessage::from)
                .collect::<Vec<HashableMessage>>()
        ),
        HashableMessage::from(
            argument.cs_upper_a.iter().map(HashableMessage::from).collect::<Vec<HashableMessage>>()
        )
    ]
}

fn get_hashable_vector_for_y<'a>(
    context: &'a ArgumentContext,
    statement: &'a ShuffleStatement,
    argument: &'a ShuffleArgument
) -> Vec<HashableMessage<'a>> {
    let mut res = get_hashable_vector_for_x(context, statement, argument);
    res.insert(
        0,
        HashableMessage::from(
            argument.cs_upper_b.iter().map(HashableMessage::from).collect::<Vec<HashableMessage>>()
        )
    );
    res
}

fn get_hashable_vector_for_z<'a>(
    context: &'a ArgumentContext,
    statement: &'a ShuffleStatement,
    argument: &'a ShuffleArgument
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
        write!(f, "productVerif: {} / multiVerif: {}", self.product_verif, self.multi_verif)
    }
}

impl ShuffleStatement {
    /// New statement taking the ownership of the data
    ///
    /// Return error if the domain is wrong
    pub fn new_owned(
        upper_cs: Vec<Ciphertext>,
        upper_c_primes: Vec<Ciphertext>
    ) -> Result<Self, ShuffleArgumentError> {
        let upper_n = upper_cs.len();
        if upper_c_primes.len() != upper_n {
            return Err(ShuffleArgumentError::LengthListCypherTextInconsistent);
        }
        let l = upper_cs[0].l();
        if upper_cs.iter().any(|c| c.l() != l) || upper_c_primes.iter().any(|c| c.l() != l) {
            return Err(ShuffleArgumentError::LengthCypherTextInconsistent);
        }
        Ok(Self { upper_cs, upper_c_primes })
    }

    /// New statement cloning the data
    ///
    /// Return error if the domain is wrong
    pub fn new(
        upper_cs: &[Ciphertext],
        upper_c_primes: &[Ciphertext]
    ) -> Result<Self, ShuffleArgumentError> {
        Self::new_owned(upper_cs.to_vec(), upper_c_primes.to_vec())
    }

    pub fn l(&self) -> usize {
        self.upper_cs[0].l()
    }

    pub fn upper_n(&self) -> usize {
        self.upper_cs.len()
    }
}

impl ShuffleArgument {
    /// New statement taking the ownership of the data
    ///
    /// Return error if the domain is wrong
    pub fn new_owned(
        cs_upper_a: Vec<MPInteger>,
        cs_upper_b: Vec<MPInteger>,
        product_argument: ProductArgument,
        multi_exponentiation_argument: MultiExponentiationArgument
    ) -> Result<Self, ShuffleArgumentError> {
        let m = cs_upper_a.len();
        let n = multi_exponentiation_argument.n();
        if cs_upper_b.len() != m {
            return Err(ShuffleArgumentError::MNotConsistent("c_B".to_string()));
        }
        if multi_exponentiation_argument.m() != m {
            return Err(
                ShuffleArgumentError::MNotConsistent("multiExponentiationArgument".to_string())
            );
        }
        if product_argument.m() != m {
            return Err(ShuffleArgumentError::MNotConsistent("ProductArgmuent".to_string()));
        }
        if let Some(p_n) = product_argument.n() {
            if p_n != n {
                return Err(ShuffleArgumentError::NNotConsistent("ProductArgmuent".to_string()));
            }
        }
        Ok(Self {
            cs_upper_a,
            cs_upper_b,
            product_argument,
            multi_exponentiation_argument,
        })
    }

    /// New statement cloning the data
    ///
    /// Return error if the domain is wrong
    pub fn new(
        cs_upper_a: &[MPInteger],
        cs_upper_b: &[MPInteger],
        product_argument: &ProductArgument,
        multi_exponentiation_argument: &MultiExponentiationArgument
    ) -> Result<Self, ShuffleArgumentError> {
        Self::new_owned(
            cs_upper_a.to_vec(),
            cs_upper_b.to_vec(),
            product_argument.clone(),
            multi_exponentiation_argument.clone()
        )
    }

    pub fn m(&self) -> usize {
        self.cs_upper_a.len()
    }

    pub fn n(&self) -> usize {
        self.multi_exponentiation_argument.n()
    }
}

impl<'a> ShuffleArgumentVerifyInput<'a> {
    /// New Input
    ///
    /// Return error if the domain is wrong
    pub fn new(
        context: &ArgumentContext,
        statement: &'a ShuffleStatement,
        argument: &'a ShuffleArgument
    ) -> Result<Self, ShuffleArgumentError> {
        if statement.upper_n() != argument.m() * argument.n() {
            return Err(ShuffleArgumentError::NNotProductOfNAndM);
        }
        if statement.l() == 0 && statement.l() > context.pks.len() {
            return Err(ShuffleArgumentError::LNotInRange);
        }
        if argument.n() < 2 || argument.n() > context.ck.nu() {
            return Err(ShuffleArgumentError::SmallNWorng(argument.n(), context.ck.nu()));
        }
        Ok(Self { statement, argument })
    }
}

#[cfg(test)]
mod test {
    use std::path::Path;
    use super::*;
    use serde_json::Value;
    use super::super::{
        multi_exponentiation_argument::test::{ get_argument as get_me_argument, get_ciphertexts },
        product_argument::test::get_argument as get_product_argument,
        test::context_from_json_value,
    };
    use crate::test_json_data::json_array_value_to_array_mpinteger;

    fn get_test_cases() -> Vec<Value> {
        let test_file = Path::new("./")
            .join("test_data")
            .join("mixnet")
            .join("verify-shuffle-argument.json");
        let json = std::fs::read_to_string(test_file).unwrap();
        serde_json::from_str(&json).unwrap()
    }

    fn get_context(tc: &Value) -> ArgumentContext {
        context_from_json_value(&tc["context"])
    }

    fn get_statement(statement: &Value) -> ShuffleStatement {
        ShuffleStatement::new(
            &get_ciphertexts(&statement["ciphertexts"]),
            &get_ciphertexts(&statement["shuffled_ciphertexts"])
        ).unwrap()
    }

    fn get_argument(argument: &Value) -> ShuffleArgument {
        ShuffleArgument::new(
            &json_array_value_to_array_mpinteger(&argument["ca"]),
            &json_array_value_to_array_mpinteger(&argument["cb"]),
            &get_product_argument(&argument["product_argument"]),
            &get_me_argument(&argument["multi_exp_argument"])
        ).unwrap()
    }

    #[test]
    fn test_verify() {
        for tc in get_test_cases().iter() {
            let context = get_context(tc);
            let statement = get_statement(&tc["input"]["statement"]);
            let argument = get_argument(&tc["input"]["argument"]);
            let input = ShuffleArgumentVerifyInput::new(&context, &statement, &argument).unwrap();
            let x_res = verify_shuffle_argument(&context, &input);
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
