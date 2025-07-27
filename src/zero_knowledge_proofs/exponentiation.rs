// Copyright © 2023 Denis Morel

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
// <https://www.gnu.org/licenses/>.

use crate::{
    elgamal::{EncryptionParameterDomainError, EncryptionParameters},
    integer::ModExponentiateError,
    number_theory::{QuadraticResidueError, QuadraticResidueTrait},
    HashError, HashableMessage, Integer, IntegerOperationError, OperationsTrait,
    RecursiveHashTrait, VerifyDomainTrait,
};
use std::iter::zip;
use thiserror::Error;

#[derive(Error, Debug)]
#[error(transparent)]
/// Error during exponentiation proofs
pub struct ExponentiationProofError(#[from] ExponentiationProofErrorRepr);

#[derive(Error, Debug)]
pub enum PhiExpError {
    #[error("Error calculating g^x mod p")]
    GExpXModP { source: ModExponentiateError },
}

#[derive(Error, Debug)]
#[allow(clippy::enum_variant_names)]
enum ExponentiationProofErrorRepr {
    #[error("Error checking the elgamal parameters")]
    CheckElgamal(Vec<EncryptionParameterDomainError>),
    #[error("The list {0} must have the same length as the list {1}")]
    CheckListSameSize(String, String),
    #[error("{name} is not qudartic residue at position {pos}")]
    NotQuadraticResidueList {
        name: &'static str,
        pos: usize,
        source: QuadraticResidueError,
    },
    #[error("Error Compute Phi Exponentiation")]
    PhiExpError {
        #[from]
        source: PhiExpError,
    },
    #[error("Error hashing e'")]
    EPrimeHash { source: HashError },
    #[error("Error in y^e mod p claculting cs'")]
    YExpEModP { source: ModExponentiateError },
    #[error("Error in v^(-1) mod p claculting cs'")]
    InverseVModP { source: IntegerOperationError },
}

/// Compute phi exponation according to specifications of Swiss Post (Algorithm 10.7)
fn compute_phi_exponentiation(
    ep: &EncryptionParameters,
    x: &Integer,
    gs: &[&Integer],
) -> Result<Vec<Integer>, PhiExpError> {
    gs.iter()
        .map(|g| {
            g.mod_exponentiate(x, ep.p())
                .map_err(|e| PhiExpError::GExpXModP { source: e })
        })
        .collect::<Result<Vec<_>, _>>()
}

/// Verify Exponation proof according to specifications of Swiss Post (Algorithm 10.9)
///
/// # Error
/// Return an error if preconditions are not satisfied
pub fn verify_exponentiation(
    ep: &EncryptionParameters,
    gs: &[&Integer],
    ys: &[&Integer],
    (e, z): (&Integer, &Integer),
    i_aux: &Vec<String>,
) -> Result<bool, ExponentiationProofError> {
    verify_exponentiation_impl(ep, gs, ys, (e, z), i_aux).map_err(ExponentiationProofError::from)
}

fn verify_exponentiation_impl(
    ep: &EncryptionParameters,
    gs: &[&Integer],
    ys: &[&Integer],
    (e, z): (&Integer, &Integer),
    i_aux: &Vec<String>,
) -> Result<bool, ExponentiationProofErrorRepr> {
    // Check of input parameters
    if cfg!(feature = "checks") {
        let domain_errs = ep.verifiy_domain();
        if !domain_errs.is_empty() {
            return Err(ExponentiationProofErrorRepr::CheckElgamal(domain_errs));
        }
        if gs.len() != ys.len() {
            return Err(ExponentiationProofErrorRepr::CheckListSameSize(
                "gs".to_string(),
                "ys".to_string(),
            ));
        }
        for (pos, g) in gs.iter().enumerate() {
            g.result_is_quadratic_residue_unchecked(ep.p())
                .map_err(|e| ExponentiationProofErrorRepr::NotQuadraticResidueList {
                    pos,
                    name: "g",
                    source: e,
                })?;
        }
        for (pos, y) in ys.iter().enumerate() {
            y.result_is_quadratic_residue_unchecked(ep.p())
                .map_err(|e| ExponentiationProofErrorRepr::NotQuadraticResidueList {
                    pos,
                    name: "y",
                    source: e,
                })?;
        }
    }

    let xs = compute_phi_exponentiation(ep, z, gs)?;
    let f_list = vec![
        HashableMessage::from(ep.p()),
        HashableMessage::from(ep.q()),
        HashableMessage::from(
            gs.iter()
                .map(|g| HashableMessage::from(*g))
                .collect::<Vec<_>>(),
        ),
    ];
    let f = HashableMessage::from(&f_list);
    let c_prime_s = zip(&xs, ys)
        .map(|(x, y)| {
            y.mod_exponentiate(e, ep.p())
                .map_err(|e| ExponentiationProofErrorRepr::YExpEModP { source: e })
                .and_then(|v| {
                    v.mod_inverse(ep.p())
                        .map_err(|e| ExponentiationProofErrorRepr::InverseVModP { source: e })
                })
                .map(|v| x.mod_multiply(&v, ep.p()))
        })
        //.map(|(x, y)| x.mod_multiply(&y.mod_exponentiate(e, ep.p()).mod_inverse(ep.p()), ep.p()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut h_aux_l: Vec<HashableMessage> = vec![];
    h_aux_l.push(HashableMessage::from("ExponentiationProof"));
    if !i_aux.is_empty() {
        h_aux_l.push(HashableMessage::from(i_aux.as_slice()));
    }
    let h_aux = HashableMessage::from(&h_aux_l);
    let l_final: Vec<HashableMessage> = vec![
        f,
        HashableMessage::from(
            ys.iter()
                .map(|y| HashableMessage::from(*y))
                .collect::<Vec<_>>(),
        ),
        HashableMessage::from(c_prime_s.as_slice()),
        h_aux,
    ];
    let e_prime = HashableMessage::from(&l_final)
        .recursive_hash()
        .map_err(|e| ExponentiationProofErrorRepr::EPrimeHash { source: e })?
        .into_integer();
    Ok(&e_prime == e)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        test_json_data::{
            json_value_to_encryption_parameters, get_test_cases_from_json_file, json_array_64_value_to_array_integer,
            json_array_value_to_array_string,
        },
        zero_knowledge_proofs::test::{proof_from_json_values, Proof},
    };
    use serde_json::Value;

    struct Input {
        bases: Vec<Integer>,
        statement: Vec<Integer>,
        proof: Proof,
        additional_information: Vec<String>,
    }

    fn get_input(input: &Value) -> Input {
        Input {
            bases: json_array_64_value_to_array_integer(&input["bases"]),
            statement: json_array_64_value_to_array_integer(&input["statement"]),
            proof: proof_from_json_values(&input["proof"]),
            additional_information: json_array_value_to_array_string(
                &input["additional_information"],
            ),
        }
    }

    #[test]
    fn test_verify() {
        for tc in get_test_cases_from_json_file("zeroknowledgeproofs", "verify-exponentiation.json") {
            let ep = json_value_to_encryption_parameters(&tc["context"]);
            let input = get_input(&tc["input"]);
            let res = verify_exponentiation(
                &ep,
                input.bases.iter().collect::<Vec<_>>().as_slice(),
                input.statement.iter().collect::<Vec<_>>().as_slice(),
                (&input.proof.e, &input.proof.z),
                &input.additional_information,
            );
            assert!(res.is_ok(), "{}", &tc["description"]);
            assert!(res.unwrap(), "{}", &tc["description"])
        }
    }
}
