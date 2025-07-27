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

use thiserror::Error;

use crate::{
    elgamal::{Ciphertext, EncryptionParameters},
    integer::ModExponentiateError,
    HashError, HashableMessage, Integer, IntegerOperationError, OperationsTrait,
    RecursiveHashTrait,
};

#[derive(Error, Debug)]
#[error(transparent)]
/// Error during decrpytion proofs
pub struct DecryptionProofError(#[from] DecryptionProofErrorRepr);

#[derive(Error, Debug)]
enum ComputePhiDecryptionError {
    #[error("Error calculating g^x mod p")]
    GExpXModP { source: ModExponentiateError },
    #[error("Error calculating base^x mod p")]
    BaseExpXModP { source: ModExponentiateError },
}

#[derive(Error, Debug)]
enum DecryptionProofErrorRepr {
    #[error("Error Compute Phi Decryption")]
    ComputePhiDecryption {
        #[from]
        source: ComputePhiDecryptionError,
    },
    #[error("l must be positive")]
    LPositive(usize),
    #[error(
        "Validate l: The length {0} of the message m must be the same the for the array phi {1}"
    )]
    LNotCorrectForM(usize, usize),
    #[error(
        "Validate l: The length {0} of the proofs z must be the same the for the array phi {1}"
    )]
    LNotCorrectForZ(usize, usize),
    #[error("l={0} must be smaller or equal to k={1}")]
    LSmallerOrEqualK(usize, usize),
    #[error("Error in phi/m mod p calculting ys")]
    PhiDivMModP { source: IntegerOperationError },
    #[error("Error in y^e mod p claculting cs'")]
    YExpEModP { source: ModExponentiateError },
    #[error("Error in v^(-1) mod p claculting cs'")]
    InverseVModP { source: IntegerOperationError },
    #[error("Error hashing e'")]
    EPrimeHash { source: HashError },
}

fn compute_phi_decryption(
    ep: &EncryptionParameters,
    pre_images: &[Integer],
    base: &Integer,
) -> Result<Vec<Integer>, ComputePhiDecryptionError> {
    pre_images
        .iter()
        .map(|x| {
            ep.g()
                .mod_exponentiate(x, ep.p())
                .map_err(|e| ComputePhiDecryptionError::GExpXModP { source: e })
        })
        .chain(pre_images.iter().map(|x| {
            base.mod_exponentiate(x, ep.p())
                .map_err(|e| ComputePhiDecryptionError::BaseExpXModP { source: e })
        }))
        .collect()
}

pub fn verify_decryption(
    ep: &EncryptionParameters,
    upper_c: &Ciphertext,
    pks: &[Integer],
    ms: &[Integer],
    i_aux: &[String],
    (e, zs): (&Integer, &[Integer]),
) -> Result<bool, DecryptionProofError> {
    verify_decryption_impl(ep, upper_c, pks, ms, i_aux, (e, zs)).map_err(DecryptionProofError::from)
}

fn verify_decryption_impl(
    ep: &EncryptionParameters,
    upper_c: &Ciphertext,
    pks: &[Integer],
    ms: &[Integer],
    i_aux: &[String],
    (e, zs): (&Integer, &[Integer]),
) -> Result<bool, DecryptionProofErrorRepr> {
    let l = upper_c.phis.len();
    let k = pks.len();
    if l == 0 {
        return Err(DecryptionProofErrorRepr::LPositive(l));
    }
    if l != ms.len() {
        return Err(DecryptionProofErrorRepr::LNotCorrectForM(ms.len(), l));
    }
    if l != zs.len() {
        return Err(DecryptionProofErrorRepr::LNotCorrectForZ(zs.len(), l));
    }
    if l > k {
        return Err(DecryptionProofErrorRepr::LSmallerOrEqualK(l, k));
    }
    let xs = compute_phi_decryption(ep, zs, &upper_c.gamma)?;
    let fs = vec![ep.p(), ep.q(), ep.g(), &upper_c.gamma];
    let ys = pks
        .iter()
        .take(l)
        .cloned()
        .map(Ok)
        .chain(upper_c.phis.iter().zip(ms.iter()).map(|(phi, m)| {
            phi.mod_divide(m, ep.p())
                .map_err(|e| DecryptionProofErrorRepr::PhiDivMModP { source: e })
        }))
        .collect::<Result<Vec<_>, _>>()?;
    let c_primes = xs
        .iter()
        .zip(ys.iter())
        .map(|(x, y)| {
            y.mod_exponentiate(e, ep.p())
                .map_err(|e| DecryptionProofErrorRepr::YExpEModP { source: e })
                .and_then(|v| {
                    v.mod_inverse(ep.p())
                        .map_err(|e| DecryptionProofErrorRepr::InverseVModP { source: e })
                })
                .map(|v| x.mod_multiply(&v, ep.p()))
        })
        //.map(|(x, y)| x.mod_multiply(&y.mod_exponentiate(e, ep.p()).mod_inverse(ep.p()), ep.p()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut h_aux: Vec<HashableMessage> = vec![
        HashableMessage::from("DecryptionProof"),
        HashableMessage::from(upper_c.phis.as_slice()),
        HashableMessage::from(ms),
    ];
    if !i_aux.is_empty() {
        h_aux.push(HashableMessage::from(i_aux));
    }
    let e_prime = HashableMessage::from(vec![
        HashableMessage::from(fs.as_slice()),
        HashableMessage::from(ys.as_slice()),
        HashableMessage::from(c_primes.as_slice()),
        HashableMessage::from(h_aux),
    ])
    .recursive_hash()
    .map_err(|e| DecryptionProofErrorRepr::EPrimeHash { source: e })?
    .into_integer();
    Ok(&e_prime == e)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        test_json_data::{
            ep_from_json_value, get_ciphertext_values, json_array_64_value_to_array_integer,
            json_array_value_to_array_string, CiphertextValues,
        },
        zero_knowledge_proofs::test::{proof_vec_from_json_values, ProofVec},
    };
    use serde_json::Value;
    use std::path::Path;

    #[test]
    fn test_compute_phi_decryption() {
        let (p, q, g) = (Integer::from(27), Integer::from(7), Integer::from(2));
        let res = compute_phi_decryption(
            &EncryptionParameters::from((&p, &q, &g)),
            &[Integer::from(3), Integer::from(5)],
            &Integer::from(13),
        );
        assert_eq!(
            res.unwrap(),
            [
                Integer::from(8),
                Integer::from(5),
                Integer::from(10),
                Integer::from(16),
            ]
        )
    }

    fn get_test_cases() -> Vec<Value> {
        let test_file = Path::new("./")
            .join("test_data")
            .join("zeroknowledgeproofs")
            .join("verify-decryption.json");
        let json = std::fs::read_to_string(test_file).unwrap();
        serde_json::from_str(&json).unwrap()
    }

    struct Input {
        ciphertext: CiphertextValues,
        public_key: Vec<Integer>,
        message: Vec<Integer>,
        proof: ProofVec,
        additional_information: Vec<String>,
    }

    fn get_input(input: &Value) -> Input {
        Input {
            ciphertext: get_ciphertext_values(&input["ciphertext"]),
            public_key: json_array_64_value_to_array_integer(&input["public_key"]),
            message: json_array_64_value_to_array_integer(&input["message"]),
            proof: proof_vec_from_json_values(&input["proof"]),
            additional_information: json_array_value_to_array_string(
                &input["additional_information"],
            ),
        }
    }

    #[test]
    fn test_verify() {
        for tc in get_test_cases() {
            let ep = ep_from_json_value(&tc["context"]);
            let input = get_input(&tc["input"]);
            let res = verify_decryption(
                &ep,
                &Ciphertext::from_expanded(&input.ciphertext.gamma, &input.ciphertext.phis),
                &input.public_key,
                &input.message,
                &input.additional_information,
                (&input.proof.e, &input.proof.z),
            );
            assert!(res.is_ok(), "{}", &tc["description"]);
            assert!(res.unwrap(), "{}", &tc["description"])
        }
    }
}
