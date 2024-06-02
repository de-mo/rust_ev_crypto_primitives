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

use std::fmt::Display;

use thiserror::Error;

use crate::{
    integer::MPInteger,
    mix_net::{
        commitments::{ get_commitment, CommitmentError },
        matrix::Matrix,
        MixNetResultTrait,
    },
    Ciphertext,
    Constants,
    ElgamalError,
    HashError,
    HashableMessage,
    Operations,
    RecursiveHashTrait,
};

use super::{ ArgumentContext, StarMapError };

/// Statement in input of the verify algorithm
#[derive(Debug, Clone)]
pub struct MultiExponentiationStatement {
    ciphertext_matrix: Matrix<Ciphertext>,
    upper_c: Ciphertext,
    cs_upper_a: Vec<MPInteger>,
}

/// Argument in input of the verify algorithm
#[derive(Debug, Clone)]
pub struct MultiExponentiationArgument {
    pub c_upper_a_0: MPInteger,
    pub cs_upper_b: Vec<MPInteger>,
    pub upper_es: Vec<Ciphertext>,
    pub a_vec: Vec<MPInteger>,
    pub r: MPInteger,
    pub b: MPInteger,
    pub s: MPInteger,
    pub tau: MPInteger,
}

/// Input of the verify algorithm
#[derive(Debug, Clone)]
pub struct MultiExponentiationArgumentVerifyInput<'a> {
    statement: &'a MultiExponentiationStatement,
    argument: &'a MultiExponentiationArgument,
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
    #[error("Ciphertext not same l")]
    CyphertextNotSameL,
    #[error("Commitment vectors c_b is not equal to ciphertext vector")]
    CommitmentVectorNotSameLen,
    #[error("{0} is not consistent")] ValueNotConsistent(String),
    #[error("{0} is too small")] SizeTooSmall(String),
    #[error("HashError: {0}")] HashError(#[from] HashError),
    #[error("CommitmentError: {0}")] CommitmentError(#[from] CommitmentError),
    #[error("StarMapError: {0}")] StarMapError(#[from] StarMapError),
    #[error("ElgamalError: {0}")] ElgamalError(#[from] ElgamalError),
}

/// Algorithm 9.16
pub fn verify_multi_exponentiation_argument(
    context: &ArgumentContext,
    input: &MultiExponentiationArgumentVerifyInput
) -> Result<MultiExponentiationArgumentResult, MultiExponentiationArgumentError> {
    let statement = input.statement;
    let argument = input.argument;
    let p = context.ep.p();
    let q = context.ep.q();
    let g = context.ep.g();
    let m = statement.m();
    let l = statement.l();

    let x = get_x(context, statement, argument)?;
    let x_powers = (0..2 * m)
        .map(|i| x.mod_exponentiate(&MPInteger::from(i), q))
        .collect::<Vec<_>>();
    println!("x_powers: {:?}", x_powers);
    println!("cs_upper_a: {:?}", statement.cs_upper_a);

    let verif_upper_c_b_m = &argument.cs_upper_b[m] == MPInteger::one();
    let verif_upper_e_m = argument.upper_es[m] == statement.upper_c;

    let prod_upper_c_a = statement.cs_upper_a
        .iter()
        .zip(x_powers.iter().skip(1))
        .map(|(c_a_i, x_i)| {
            println!("c_a_i: {}, x_i: {}", c_a_i, x_i);
            c_a_i.mod_exponentiate(x_i, p)
        })
        .fold(argument.c_upper_a_0.clone(), |acc, v| acc.mod_multiply(&v, p));
    let comm_upper_a = get_commitment(
        &context.ep,
        &argument.a_vec,
        &argument.r,
        &context.ck
    ).map_err(MultiExponentiationArgumentError::CommitmentError)?;
    let verif_upper_a = prod_upper_c_a == comm_upper_a;

    let prod_upper_c_b = argument.cs_upper_b
        .iter()
        .zip(x_powers.iter())
        .skip(1)
        .map(|(c_b_k, x_k)| c_b_k.mod_exponentiate(x_k, p))
        .fold(argument.cs_upper_b[0].clone(), |acc, v| acc.mod_multiply(&v, p));
    let comm_upper_b = get_commitment(
        &context.ep,
        &[argument.b.clone()],
        &argument.s,
        &context.ck
    ).map_err(MultiExponentiationArgumentError::CommitmentError)?;
    let verif_upper_b = prod_upper_c_b == comm_upper_b;

    let prod_upper_e = argument.upper_es
        .iter()
        .zip(x_powers.iter())
        .skip(1)
        .map(|(e_k, x_k)| e_k.get_ciphertext_exponentiation(x_k, &context.ep))
        .fold(argument.upper_es[0].clone(), |acc, e| acc.get_ciphertext_product(&e, &context.ep));
    let encrypted_upper_g_b = Ciphertext::get_ciphertext(
        &context.ep,
        vec![g.mod_exponentiate(&argument.b, p); l].as_slice(),
        &argument.tau,
        &context.pks
    ).map_err(MultiExponentiationArgumentError::ElgamalError)?;
    let prod_c = statement.ciphertext_matrix
        .rows_iter()
        .zip(x_powers.iter().take(m).rev())
        .map(|(c_i, x_m_minus_i_minus_1)|
            Ciphertext::get_ciphertext_vector_exponentiation(
                c_i.into_iter().cloned().collect::<Vec<_>>().as_slice(),
                x_m_minus_i_minus_1.mod_scalar_multiply(argument.a_vec.as_slice(), p).as_slice(),
                &context.ep
            )
        )
        .fold(Ciphertext::neutral_for_mod_multiply(l), |acc, c|
            acc.get_ciphertext_product(&c, &context.ep)
        );
    let verif_upper_e_upper_c =
        prod_upper_e == encrypted_upper_g_b.get_ciphertext_product(&prod_c, &context.ep);

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
    argument: &MultiExponentiationArgument
) -> Result<MPInteger, MultiExponentiationArgumentError> {
    Ok(
        HashableMessage::from(
            vec![
                HashableMessage::from(context.ep.p()),
                HashableMessage::from(context.ep.q()),
                HashableMessage::from(&context.pks),
                HashableMessage::from(&context.ck),
                HashableMessage::from(&statement.ciphertext_matrix),
                HashableMessage::from(&statement.upper_c),
                HashableMessage::from(&statement.cs_upper_a),
                HashableMessage::from(&argument.c_upper_a_0),
                HashableMessage::from(&argument.cs_upper_b),
                HashableMessage::from(&argument.upper_es)
            ]
        )
            .recursive_hash()
            .map_err(MultiExponentiationArgumentError::HashError)?
            .into_mp_integer()
    )
}

impl MultiExponentiationStatement {
    /// New statement taking the ownership of the data
    ///
    /// Return error if the domain is wrong
    pub fn new_owned(
        ciphertext_matrix: Matrix<Ciphertext>,
        upper_c: Ciphertext,
        cs_upper_a: Vec<MPInteger>
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
                return Err(MultiExponentiationArgumentError::CyphertextNotSameL);
            }
        }
        Ok(Self { ciphertext_matrix, upper_c, cs_upper_a })
    }

    /// New statement cloning the data
    ///
    /// Return error if the domain is wrong
    pub fn new(
        ciphertext_matrix: &Matrix<Ciphertext>,
        upper_c: &Ciphertext,
        cs_upper_a: &[MPInteger]
    ) -> Result<Self, MultiExponentiationArgumentError> {
        Self::new_owned(ciphertext_matrix.clone(), upper_c.clone(), cs_upper_a.to_vec())
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

impl MultiExponentiationArgument {
    /// New statement taking the ownership of the data
    ///
    /// Return error if the domain is wrong
    pub fn new_owned(
        c_upper_a_0: MPInteger,
        cs_upper_b: Vec<MPInteger>,
        upper_es: Vec<Ciphertext>,
        a_vec: Vec<MPInteger>,
        r: MPInteger,
        b: MPInteger,
        s: MPInteger,
        tau: MPInteger
    ) -> Result<Self, MultiExponentiationArgumentError> {
        if cs_upper_b.len() != upper_es.len() {
            return Err(MultiExponentiationArgumentError::CommitmentVectorNotSameLen);
        }
        let l = upper_es[0].l();
        if !upper_es.iter().all(|e| e.l() == l) {
            return Err(MultiExponentiationArgumentError::CyphertextNotSameL);
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

    /// New statement cloning the data
    ///
    /// Return error if the domain is wrong
    pub fn new(
        c_upper_a_0: &MPInteger,
        cs_upper_b: &[MPInteger],
        upper_es: &[Ciphertext],
        a_vec: &[MPInteger],
        r: &MPInteger,
        b: &MPInteger,
        s: &MPInteger,
        tau: &MPInteger
    ) -> Result<Self, MultiExponentiationArgumentError> {
        Self::new_owned(
            c_upper_a_0.clone(),
            cs_upper_b.to_vec(),
            upper_es.to_vec(),
            a_vec.to_vec(),
            r.clone(),
            b.clone(),
            s.clone(),
            tau.clone()
        )
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

impl<'a> MultiExponentiationArgumentVerifyInput<'a> {
    /// New Input
    ///
    /// Return error if the domain is wrong
    pub fn new(
        statement: &'a MultiExponentiationStatement,
        argument: &'a MultiExponentiationArgument
    ) -> Result<Self, MultiExponentiationArgumentError> {
        if statement.m() != argument.m() {
            return Err(MultiExponentiationArgumentError::ValueNotConsistent("m".to_string()));
        }
        if statement.n() != argument.n() {
            return Err(MultiExponentiationArgumentError::ValueNotConsistent("n".to_string()));
        }
        if statement.l() != argument.l() {
            return Err(MultiExponentiationArgumentError::ValueNotConsistent("l".to_string()));
        }
        if statement.m() == 0 {
            return Err(MultiExponentiationArgumentError::SizeTooSmall("m".to_string()));
        }
        if statement.n() == 0 {
            return Err(MultiExponentiationArgumentError::SizeTooSmall("n".to_string()));
        }
        Ok(Self { statement, argument })
    }
}

impl MixNetResultTrait for MultiExponentiationArgumentResult {
    fn is_ok(&self) -> bool {
        self.verif_upper_a &&
            self.verif_upper_b &&
            self.verif_upper_c_b_m &&
            self.verif_upper_e_m &&
            self.verif_upper_e_upper_c
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
    use std::path::Path;
    use super::*;
    use serde_json::Value;
    use super::super::test::context_from_json_value;
    use crate::test_json_data::{ json_array_value_to_array_mpinteger, json_value_to_mpinteger };

    fn get_test_cases() -> Vec<Value> {
        let test_file = Path::new("./")
            .join("test_data")
            .join("mixnet")
            .join("verify-multiexp-argument.json");
        let json = std::fs::read_to_string(test_file).unwrap();
        serde_json::from_str(&json).unwrap()
    }

    fn get_context(tc: &Value) -> ArgumentContext {
        context_from_json_value(&tc["context"])
    }

    pub fn get_ciphertexts(value: &Value) -> Vec<Ciphertext> {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|e| get_ciphertext(e))
            .collect()
    }

    pub fn get_ciphertext_matrix(value: &Value) -> Matrix<Ciphertext> {
        let temp: Vec<Vec<Ciphertext>> = value
            .as_array()
            .unwrap()
            .iter()
            .map(get_ciphertexts)
            .collect();
        let m = temp.len();
        let n = temp[0].len();
        Matrix::to_matrix(&temp.into_iter().flatten().collect::<Vec<_>>(), (n, m))
            .unwrap()
            .transpose()
            .unwrap()
    }

    fn get_ciphertext(tc: &Value) -> Ciphertext {
        Ciphertext::from_expanded(
            &json_value_to_mpinteger(&tc["gamma"]),
            &json_array_value_to_array_mpinteger(&tc["phis"])
        )
    }

    fn get_statement(statement: &Value) -> MultiExponentiationStatement {
        MultiExponentiationStatement::new_owned(
            get_ciphertext_matrix(&statement["ciphertexts"]),
            get_ciphertext(&statement["ciphertext_product"]),
            json_array_value_to_array_mpinteger(&statement["c_a"])
        ).unwrap()
    }

    pub fn get_argument(argument: &Value) -> MultiExponentiationArgument {
        MultiExponentiationArgument::new_owned(
            json_value_to_mpinteger(&argument["c_a_0"]),
            json_array_value_to_array_mpinteger(&argument["c_b"]),
            get_ciphertexts(&argument["e"]),
            json_array_value_to_array_mpinteger(&argument["a"]),
            json_value_to_mpinteger(&argument["r"]),
            json_value_to_mpinteger(&argument["b"]),
            json_value_to_mpinteger(&argument["s"]),
            json_value_to_mpinteger(&argument["tau"])
        ).unwrap()
    }

    #[test]
    fn test_verify() {
        for tc in get_test_cases().iter().skip(1) {
            let statement = get_statement(&tc["input"]["statement"]);
            let argument = get_argument(&tc["input"]["argument"]);
            let input = MultiExponentiationArgumentVerifyInput::new(&statement, &argument).unwrap();
            let x_res = verify_multi_exponentiation_argument(&get_context(tc), &input);
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
