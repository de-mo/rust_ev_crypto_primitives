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

//! Module implementing the verification for the Multi-Exponentiation Argument (§9.3.2)

use std::{fmt::Display, ops::ControlFlow};

use thiserror::Error;

use crate::{
    elgamal::{Ciphertext, ElgamalError},
    integer::ModExponentiateError,
    mix_net::{
        commitments::{get_commitment, CommitmentError},
        matrix::Matrix,
        MixNetResultTrait, MixnetError, MixnetErrorRepr,
    },
    ConstantsTrait, HashError, HashableMessage, Integer, IntegerOperationError, OperationsTrait,
    RecursiveHashTrait,
};

use super::ArgumentContext;

/// Statement in input of the verify algorithm
#[derive(Debug, Clone)]
pub struct MultiExponentiationStatement<'a> {
    ciphertext_matrix: &'a Matrix<Ciphertext>,
    upper_c: &'a Ciphertext,
    cs_upper_a: &'a [Integer],
}

/// Argument in input of the verify algorithm
#[derive(Debug, Clone)]
pub struct MultiExponentiationArgument<'a> {
    pub c_upper_a_0: &'a Integer,
    pub cs_upper_b: &'a [Integer],
    pub upper_es: &'a [Ciphertext],
    pub a_vec: &'a [Integer],
    pub r: &'a Integer,
    pub b: &'a Integer,
    pub s: &'a Integer,
    pub tau: &'a Integer,
}

/// Input of the verify algorithm
#[derive(Debug, Clone)]
pub struct MultiExponentiationArgumentVerifyInput<'a, 'b> {
    statement: &'a MultiExponentiationStatement<'a>,
    argument: &'b MultiExponentiationArgument<'b>,
}

/// Result of the verify algorithm, according to the specifications
#[derive(Debug, Eq, PartialEq)]
pub struct MultiExponentiationArgumentResult {
    pub verif_upper_c_b_m: bool,
    pub verif_upper_e_m: bool,
    pub verif_upper_a: bool,
    pub verif_upper_b: bool,
    pub verif_upper_e_upper_c: bool,
}

/// Error during the process
#[derive(Error, Debug)]
pub enum MultiExponentiationArgumentError {
    #[error("Ciphertext matrix is malformed")]
    CyphertextMatrixMalformed,
    #[error("Ciphertext not same length in {0}")]
    CyphertextNotSameL(String),
    #[error("Commitment vectors c_b is not equal to ciphertext vector")]
    CommitmentVectorNotSameLen,
    #[error("{0} is not consistent")]
    ValueNotConsistent(String),
    #[error("{0} is too small")]
    SizeTooSmall(String),
    #[error("Error for x")]
    X { source: HashError },
    #[error("Error calculating the pwoers of x")]
    XPowers { source: ModExponentiateError },
    #[error("Error calculating the product of A")]
    ProdA { source: IntegerOperationError },
    #[error("error calculation Commitment A")]
    CommitmentA { source: CommitmentError },
    #[error("Error calculating the product of B")]
    ProdB { source: IntegerOperationError },
    #[error("error calculation Commitment B")]
    CommitmentB { source: CommitmentError },
    #[error("error calculation product E")]
    ProdE { source: ElgamalError },
    #[error("error calculation g^b mod p")]
    GExpBModP { source: ModExponentiateError },
    #[error("error encrypting g^b mod p")]
    EncryptionGExpModP { source: ElgamalError },
}

/// Algorithm 9.16
pub fn verify_multi_exponentiation_argument(
    context: &ArgumentContext,
    input: &MultiExponentiationArgumentVerifyInput,
) -> Result<MultiExponentiationArgumentResult, MultiExponentiationArgumentError> {
    let statement = input.statement;
    let argument = input.argument;
    let p = context.ep.p();
    let q = context.ep.q();
    let g = context.ep.g();
    let m = statement.m();
    let l = statement.l();

    let x = get_x(context, statement, argument)
        .map_err(|e| MultiExponentiationArgumentError::X { source: e })?;
    let x_powers = (0..2 * m)
        .map(|i| x.mod_exponentiate(&Integer::from(i), q))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| MultiExponentiationArgumentError::XPowers { source: e })?;

    let verif_upper_c_b_m = &argument.cs_upper_b[m] == Integer::one();
    let verif_upper_e_m = &argument.upper_es[m] == statement.upper_c;

    let prod_upper_c_a = argument.c_upper_a_0.mod_multiply(
        &Integer::mod_multi_exponentiate_iter(
            &mut statement.cs_upper_a.iter(),
            &mut x_powers.iter().skip(1),
            p,
        )
        .map_err(|e| MultiExponentiationArgumentError::ProdA { source: e })?,
        p,
    );
    /*statement
    .cs_upper_a
    .iter()
    .zip(x_powers.iter().skip(1))
    .map(|(c_a_i, x_i)| c_a_i.mod_exponentiate(x_i, p))
    .fold(argument.c_upper_a_0.clone(), |acc, v| {
        acc.mod_multiply(&v, p)
    });*/
    let comm_upper_a = get_commitment(context.ep, argument.a_vec, argument.r, context.ck)
        .map_err(|e| MultiExponentiationArgumentError::CommitmentA { source: e })?;
    let verif_upper_a = prod_upper_c_a == comm_upper_a;

    let prod_upper_c_b = Integer::mod_multi_exponentiate_iter(
        &mut argument.cs_upper_b.iter(),
        &mut x_powers.iter(),
        p,
    )
    .map_err(|e| MultiExponentiationArgumentError::ProdB { source: e })?;
    /*argument
    .cs_upper_b
    .iter()
    .zip(x_powers.iter())
    .skip(1)
    .map(|(c_b_k, x_k)| c_b_k.mod_exponentiate(x_k, p))
    .fold(argument.cs_upper_b[0].clone(), |acc, v| {
        acc.mod_multiply(&v, p)
    });*/
    let comm_upper_b = get_commitment(context.ep, &[argument.b.clone()], argument.s, context.ck)
        .map_err(|e| MultiExponentiationArgumentError::CommitmentB { source: e })?;
    let verif_upper_b = prod_upper_c_b == comm_upper_b;

    let prod_upper_e = match argument
        .upper_es
        .iter()
        .zip(x_powers.iter())
        .skip(1)
        .map(|(e_k, x_k)| e_k.get_ciphertext_exponentiation(x_k, context.ep))
        .try_fold(argument.upper_es[0].clone(), |acc, e_res| match e_res {
            Ok(e) => ControlFlow::Continue(acc.get_ciphertext_product(&e, context.ep)),
            Err(e) => ControlFlow::Break(e),
        }) {
        ControlFlow::Continue(v) => Ok(v),
        ControlFlow::Break(e) => Err(MultiExponentiationArgumentError::ProdE { source: e }),
    }?;
    let encrypted_upper_g_b = Ciphertext::get_ciphertext(
        context.ep,
        vec![
            g.mod_exponentiate(argument.b, p)
                .map_err(|e| MultiExponentiationArgumentError::GExpBModP { source: e })?;
            l
        ]
        .as_slice(),
        argument.tau,
        context.pks,
    )
    .map_err(|e| MultiExponentiationArgumentError::EncryptionGExpModP { source: e })?;
    let prod_c = match statement
        .ciphertext_matrix
        .rows_iter()
        .zip(x_powers.iter().take(m).rev())
        .map(|(c_i, x_m_minus_i_minus_1)| {
            Ciphertext::get_ciphertext_vector_exponentiation(
                c_i.to_vec().as_slice(),
                x_m_minus_i_minus_1
                    .mod_scalar_multiply(argument.a_vec, q)
                    .as_slice(),
                context.ep,
            )
        })
        .try_fold(
            Ciphertext::neutral_for_mod_multiply(l),
            |acc, c_res| match c_res {
                Ok(c) => ControlFlow::Continue(acc.get_ciphertext_product(&c, context.ep)),
                Err(e) => ControlFlow::Break(e),
            },
        ) {
        ControlFlow::Continue(c) => Ok(c),
        ControlFlow::Break(e) => Err(MultiExponentiationArgumentError::ProdE { source: e }),
    }?;
    let verif_upper_e_upper_c =
        prod_upper_e == encrypted_upper_g_b.get_ciphertext_product(&prod_c, context.ep);

    Ok(MultiExponentiationArgumentResult {
        verif_upper_c_b_m,
        verif_upper_e_m,
        verif_upper_a,
        verif_upper_b,
        verif_upper_e_upper_c,
    })
}

pub fn get_x(
    context: &ArgumentContext,
    statement: &MultiExponentiationStatement,
    argument: &MultiExponentiationArgument,
) -> Result<Integer, HashError> {
    Ok(HashableMessage::from(vec![
        HashableMessage::from(context.ep.p()),
        HashableMessage::from(context.ep.q()),
        HashableMessage::from(context.pks),
        HashableMessage::from(context.ck),
        HashableMessage::from(statement.ciphertext_matrix),
        HashableMessage::from(statement.upper_c),
        HashableMessage::from(statement.cs_upper_a),
        HashableMessage::from(argument.c_upper_a_0),
        HashableMessage::from(argument.cs_upper_b),
        HashableMessage::from(argument.upper_es),
    ])
    .recursive_hash()?
    .into_integer())
}

impl<'a> MultiExponentiationStatement<'a> {
    /// New statement cloning the data
    ///
    /// Return error if the domain is wrong
    pub fn new(
        ciphertext_matrix: &'a Matrix<Ciphertext>,
        upper_c: &'a Ciphertext,
        cs_upper_a: &'a [Integer],
    ) -> Result<Self, MultiExponentiationArgumentError> {
        if ciphertext_matrix.is_malformed() {
            return Err(MultiExponentiationArgumentError::CyphertextMatrixMalformed);
        }
        if ciphertext_matrix.nb_rows() != cs_upper_a.len() {
            return Err(MultiExponentiationArgumentError::CommitmentVectorNotSameLen);
        }
        let l = upper_c.l();
        for j in 0..ciphertext_matrix.nb_columns() {
            let col = ciphertext_matrix.column(j);
            if !col.iter().all(|e| e.l() == l) {
                return Err(MultiExponentiationArgumentError::CyphertextNotSameL(
                    "MultiExponentiationStatement (C to ciphertext_matrix)".to_string(),
                ));
            }
        }
        Ok(Self {
            ciphertext_matrix,
            upper_c,
            cs_upper_a,
        })
    }

    pub fn m(&self) -> usize {
        self.cs_upper_a.len()
    }

    pub fn n(&self) -> usize {
        self.ciphertext_matrix.nb_columns()
    }

    pub fn l(&self) -> usize {
        self.upper_c.l()
    }
}

#[allow(clippy::too_many_arguments)]
impl<'a> MultiExponentiationArgument<'a> {
    /// New statement
    ///
    /// Return error if the domain is wrong
    pub fn new(
        c_upper_a_0: &'a Integer,
        cs_upper_b: &'a [Integer],
        upper_es: &'a [Ciphertext],
        a_vec: &'a [Integer],
        r: &'a Integer,
        b: &'a Integer,
        s: &'a Integer,
        tau: &'a Integer,
    ) -> Result<Self, MixnetError> {
        Self::new_impl(c_upper_a_0, cs_upper_b, upper_es, a_vec, r, b, s, tau)
            .map_err(MixnetErrorRepr::from)
            .map_err(|e| MixnetError {
                source: Box::new(e),
            })
    }

    fn new_impl(
        c_upper_a_0: &'a Integer,
        cs_upper_b: &'a [Integer],
        upper_es: &'a [Ciphertext],
        a_vec: &'a [Integer],
        r: &'a Integer,
        b: &'a Integer,
        s: &'a Integer,
        tau: &'a Integer,
    ) -> Result<Self, MultiExponentiationArgumentError> {
        if cs_upper_b.len() != upper_es.len() {
            return Err(MultiExponentiationArgumentError::CommitmentVectorNotSameLen);
        }
        let l = upper_es[0].l();
        if !upper_es.iter().all(|e| e.l() == l) {
            return Err(MultiExponentiationArgumentError::CyphertextNotSameL(
                "MultiExponentiationArgument (in E)".to_string(),
            ));
        }
        Ok(Self {
            c_upper_a_0,
            cs_upper_b,
            upper_es,
            a_vec,
            r,
            b,
            s,
            tau,
        })
    }

    pub fn m(&self) -> usize {
        self.cs_upper_b.len() / 2
    }

    pub fn n(&self) -> usize {
        self.a_vec.len()
    }

    pub fn l(&self) -> usize {
        self.upper_es[0].l()
    }
}

impl<'a, 'b> MultiExponentiationArgumentVerifyInput<'a, 'b> {
    /// New Input
    ///
    /// Return error if the domain is wrong
    pub fn new(
        statement: &'a MultiExponentiationStatement<'a>,
        argument: &'b MultiExponentiationArgument<'b>,
    ) -> Result<Self, MultiExponentiationArgumentError> {
        if statement.m() != argument.m() {
            return Err(MultiExponentiationArgumentError::ValueNotConsistent(
                "m".to_string(),
            ));
        }
        if statement.n() != argument.n() {
            return Err(MultiExponentiationArgumentError::ValueNotConsistent(
                "n".to_string(),
            ));
        }
        if statement.l() != argument.l() {
            return Err(MultiExponentiationArgumentError::ValueNotConsistent(
                "l".to_string(),
            ));
        }
        if statement.m() == 0 {
            return Err(MultiExponentiationArgumentError::SizeTooSmall(
                "m".to_string(),
            ));
        }
        if statement.n() == 0 {
            return Err(MultiExponentiationArgumentError::SizeTooSmall(
                "n".to_string(),
            ));
        }
        Ok(Self {
            statement,
            argument,
        })
    }
}

impl MixNetResultTrait for MultiExponentiationArgumentResult {
    fn is_ok(&self) -> bool {
        self.verif_upper_a
            && self.verif_upper_b
            && self.verif_upper_c_b_m
            && self.verif_upper_e_m
            && self.verif_upper_e_upper_c
    }
}

impl Display for MultiExponentiationArgumentResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_ok() {
            return write!(f, "verification ok");
        }
        write!(
            f,
            "verifCbm: {}, verifEm: {}, verifA: {}, verifB: {}, verifEC: {}",
            self.verif_upper_c_b_m,
            self.verif_upper_e_m,
            self.verif_upper_a,
            self.verif_upper_b,
            self.verif_upper_e_upper_c
        )
    }
}

#[cfg(test)]
pub mod test {
    use super::super::test::context_from_json_value;
    use super::super::test::{ck_from_json_value, context_values, ep_from_json_value};
    use super::*;
    use crate::test_json_data::{json_array_exa_value_to_array_integer, json_exa_value_to_integer};
    use serde_json::Value;
    use std::path::Path;

    fn get_test_cases() -> Vec<Value> {
        let test_file = Path::new("./")
            .join("test_data")
            .join("mixnet")
            .join("verify-multiexp-argument.json");
        let json = std::fs::read_to_string(test_file).unwrap();
        serde_json::from_str(&json).unwrap()
    }

    pub fn get_ciphertexts(value: &Value) -> Vec<Ciphertext> {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(get_ciphertext)
            .collect()
    }

    pub fn get_ciphertext_matrix(value: &Value) -> Matrix<Ciphertext> {
        let temp: Vec<Vec<Ciphertext>> = value
            .as_array()
            .unwrap()
            .iter()
            .map(get_ciphertexts)
            .collect();
        Matrix::from_rows(&temp).unwrap()
    }

    fn get_ciphertext(tc: &Value) -> Ciphertext {
        Ciphertext::from_expanded(
            &json_exa_value_to_integer(&tc["gamma"]),
            &json_array_exa_value_to_array_integer(&tc["phis"]),
        )
    }

    pub struct MEStatementValues(pub Matrix<Ciphertext>, pub Ciphertext, pub Vec<Integer>);
    pub struct MEArgumentValues(
        pub Integer,
        pub Vec<Integer>,
        pub Vec<Ciphertext>,
        pub Vec<Integer>,
        pub Integer,
        pub Integer,
        pub Integer,
        pub Integer,
    );

    fn get_statement_values(statement: &Value) -> MEStatementValues {
        MEStatementValues(
            get_ciphertext_matrix(&statement["ciphertexts"]),
            get_ciphertext(&statement["ciphertext_product"]),
            json_array_exa_value_to_array_integer(&statement["c_a"]),
        )
    }

    fn get_statement(values: &MEStatementValues) -> MultiExponentiationStatement<'_> {
        MultiExponentiationStatement::new(&values.0, &values.1, &values.2).unwrap()
    }

    pub fn get_argument_values(argument: &Value) -> MEArgumentValues {
        MEArgumentValues(
            json_exa_value_to_integer(&argument["c_a_0"]),
            json_array_exa_value_to_array_integer(&argument["c_b"]),
            get_ciphertexts(&argument["e"]),
            json_array_exa_value_to_array_integer(&argument["a"]),
            json_exa_value_to_integer(&argument["r"]),
            json_exa_value_to_integer(&argument["b"]),
            json_exa_value_to_integer(&argument["s"]),
            json_exa_value_to_integer(&argument["tau"]),
        )
    }

    pub fn get_argument(values: &MEArgumentValues) -> MultiExponentiationArgument<'_> {
        MultiExponentiationArgument::new(
            &values.0, &values.1, &values.2, &values.3, &values.4, &values.5, &values.6, &values.7,
        )
        .unwrap()
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
            let input = MultiExponentiationArgumentVerifyInput::new(&statement, &argument).unwrap();
            let x_res = verify_multi_exponentiation_argument(&context, &input);
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
