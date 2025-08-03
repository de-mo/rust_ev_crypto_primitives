// Copyright © 2023 Denis Morel

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
// <https://www.gnu.org/licenses/>.

use crate::{
    elgamal::EncryptionParameters, integer::ModExponentiateError, HashError, HashableMessage,
    Integer, IntegerOperationError, OperationsTrait, RecursiveHashTrait,
};
use thiserror::Error;

#[derive(Error, Debug)]
#[error(transparent)]
/// Error during Plaintext proofs
pub struct PlaintextProofError(#[from] PlaintextProofErrorRepr);

#[derive(Error, Debug)]
enum PhiPlaintextEqualityError {
    #[error("Error calculating g^x mod p")]
    GExpXModP { source: ModExponentiateError },
    #[error("Error calculating g^x' mod p")]
    GExpXPrimeModP { source: ModExponentiateError },
    #[error("Error calculating h^... mod p")]
    HExpXPrimeModP { source: ModExponentiateError },
    #[error("Error calculating division of h^x mod p with h'^x' mod p")]
    Division { source: IntegerOperationError },
    #[error("Error calculating h'^x' mod p")]
    HPrimeExpXPrimeModP { source: ModExponentiateError },
}

#[derive(Error, Debug)]
enum PlaintextProofErrorRepr {
    #[error("Error Compute Phi Plaintext Equality")]
    PhiPlaintextEqualityError {
        #[from]
        source: PhiPlaintextEqualityError,
    },
    #[error("Error calculating c_1/c_1' mod p")]
    C1DivideCPrime1 { source: IntegerOperationError },
    #[error("Error calculating y^e mod p")]
    YExpEModP { source: ModExponentiateError },
    #[error("Error in v^(-1) mod p claculting cs'")]
    InverseVModP { source: IntegerOperationError },
    #[error("Error hashing e'")]
    EPrimeHash { source: HashError },
}

fn compute_phi_plaintext_equality(
    ep: &EncryptionParameters,
    (x, x_prime): (&Integer, &Integer),
    h: &Integer,
    h_prime: &Integer,
) -> Result<[Integer; 3], PhiPlaintextEqualityError> {
    Ok([
        ep.g()
            .mod_exponentiate(x, ep.p())
            .map_err(|e| PhiPlaintextEqualityError::GExpXModP { source: e })?,
        ep.g()
            .mod_exponentiate(x_prime, ep.p())
            .map_err(|e| PhiPlaintextEqualityError::GExpXPrimeModP { source: e })?,
        h.mod_exponentiate(x, ep.p())
            .map_err(|e| PhiPlaintextEqualityError::HExpXPrimeModP { source: e })?
            .mod_divide(
                &h_prime
                    .mod_exponentiate(x_prime, ep.p())
                    .map_err(|e| PhiPlaintextEqualityError::HPrimeExpXPrimeModP { source: e })?,
                ep.p(),
            )
            .map_err(|e| PhiPlaintextEqualityError::Division { source: e })?,
    ])
}

pub fn verify_plaintext_equality(
    ep: &EncryptionParameters,
    (c_0, c_1): (&Integer, &Integer),
    (c_prime_0, c_prime_1): (&Integer, &Integer),
    h: &Integer,
    h_prime: &Integer,
    (e, (z_0, z_1)): (&Integer, (&Integer, &Integer)),
    i_aux: &[String],
) -> Result<bool, PlaintextProofError> {
    verify_plaintext_equality_imple(
        ep,
        (c_0, c_1),
        (c_prime_0, c_prime_1),
        h,
        h_prime,
        (e, (z_0, z_1)),
        i_aux,
    )
    .map_err(PlaintextProofError::from)
}

fn verify_plaintext_equality_imple(
    ep: &EncryptionParameters,
    (c_0, c_1): (&Integer, &Integer),
    (c_prime_0, c_prime_1): (&Integer, &Integer),
    h: &Integer,
    h_prime: &Integer,
    (e, (z_0, z_1)): (&Integer, (&Integer, &Integer)),
    i_aux: &[String],
) -> Result<bool, PlaintextProofErrorRepr> {
    let xs = compute_phi_plaintext_equality(ep, (z_0, z_1), h, h_prime)
        .map_err(PlaintextProofErrorRepr::from)?;
    let fs = vec![ep.p(), ep.q(), ep.g(), h, h_prime];
    let ys = [
        c_0.clone(),
        c_prime_0.clone(),
        c_1.mod_divide(c_prime_1, ep.p())
            .map_err(|e| PlaintextProofErrorRepr::C1DivideCPrime1 { source: e })?,
    ];
    let c_prime = xs
        .iter()
        .zip(ys.iter())
        .map(|(x, y)| {
            y.mod_exponentiate(e, ep.p())
                .map_err(|e| PlaintextProofErrorRepr::YExpEModP { source: e })
                .and_then(|v| {
                    v.mod_inverse(ep.p())
                        .map_err(|e| PlaintextProofErrorRepr::InverseVModP { source: e })
                })
                .map(|v| x.mod_multiply(&v, ep.p()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut h_aux = vec![
        HashableMessage::from("PlaintextEqualityProof"),
        HashableMessage::from(c_1),
        HashableMessage::from(c_prime_1),
    ];
    if !i_aux.is_empty() {
        h_aux.push(HashableMessage::from(i_aux));
    }
    let e_prime = HashableMessage::from(vec![
        HashableMessage::from(fs),
        HashableMessage::from(ys.as_slice()),
        HashableMessage::from(c_prime.as_slice()),
        HashableMessage::from(&h_aux),
    ])
    .recursive_hash()
    .map_err(|e| PlaintextProofErrorRepr::EPrimeHash { source: e })?
    .into_integer();
    Ok(&e_prime == e)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        test_json_data::{
            get_test_cases_from_json_file, json_64_value_to_integer, json_array_value_to_array_string,
            json_value_to_encryption_parameters, json_values_to_ciphertext_values,
            CiphertextValues,
        },
        zero_knowledge_proofs::test::{proof_vec_from_json_values, ProofVec},
    };
    use serde_json::Value;

    struct Input {
        upper_c: CiphertextValues,
        upper_c_prime: CiphertextValues,
        h: Integer,
        h_prime: Integer,
        proof: ProofVec,
        i_aux: Vec<String>,
    }

    fn get_input(input: &Value) -> Input {
        Input {
            upper_c: json_values_to_ciphertext_values(&input["upper_c"]),
            upper_c_prime: json_values_to_ciphertext_values(&input["upper_c_prime"]),
            h: json_64_value_to_integer(&input["h"]),
            h_prime: json_64_value_to_integer(&input["h_prime"]),
            proof: proof_vec_from_json_values(&input["proof"]),
            i_aux: json_array_value_to_array_string(&input["i_aux"]),
        }
    }

    #[test]
    fn test_verify() {
        for tc in get_test_cases_from_json_file("zeroknowledgeproofs", "verify-plaintext-equality.json") {
            let ep = json_value_to_encryption_parameters(&tc["context"]);
            let input = get_input(&tc["input"]);
            let res = verify_plaintext_equality(
                &ep,
                (&input.upper_c.gamma, &input.upper_c.phis[0]),
                (&input.upper_c_prime.gamma, &input.upper_c_prime.phis[0]),
                &input.h,
                &input.h_prime,
                (&input.proof.e, (&input.proof.z[0], &input.proof.z[1])),
                &input.i_aux,
            );
            assert!(res.is_ok(), "{}", &tc["description"]);
            assert!(res.unwrap(), "{}", &tc["description"])
        }
    }
}
