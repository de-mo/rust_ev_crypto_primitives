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

//! Implementation of decryption algorithms

use super::{Ciphertext, ElgamalError, ElgamalErrorRepr, EncryptionParameters};
use crate::{
    zero_knowledge_proofs::{verify_decryption, DecryptionProofError},
    Integer,
};
use std::fmt::Display;
use thiserror::Error;

#[derive(Error, Debug)]
pub(super) enum DecryptionError {
    #[error("The length of the ciphertext vectors upper_n and upper_cs must be the same")]
    CipherTextVectorsLenNotSame,
    #[error("The length of the decryption proofs must be the same than the ciphertext vectors")]
    DecryptionProofLenNotSame,
    #[error("No cihpertexts")]
    NoCiphertext,
    #[error("l not consistent over the ciphertext for {name}")]
    LNotConsistentOverCiphertexts { name: &'static str },
    #[error("Error verifying the decrpytion proofs")]
    DecryptionProofError(#[from] DecryptionProofError),
}

#[derive(Debug, Clone, Copy)]
struct VerifyDecryptionResultOneCiphertext {
    verif_gamma: bool,
    verif_decryption: bool,
}

#[derive(Debug, Clone)]
pub struct VerifyDecryptionsResult {
    errors: Vec<(usize, VerifyDecryptionResultOneCiphertext)>,
}

pub fn verify_decryptions(
    ep: &EncryptionParameters,
    upper_cs: &[Ciphertext],
    pks: &[Integer],
    upper_cs_prime: &[Ciphertext],
    pi_dec: &[(&Integer, &[Integer])],
    i_aux: &[String],
) -> Result<VerifyDecryptionsResult, ElgamalError> {
    verify_decryptions_impl(ep, upper_cs, pks, upper_cs_prime, pi_dec, i_aux)
        .map_err(ElgamalErrorRepr::from)
        .map_err(ElgamalError::from)
}

fn verify_decryptions_impl(
    ep: &EncryptionParameters,
    upper_cs: &[Ciphertext],
    pks: &[Integer],
    upper_cs_prime: &[Ciphertext],
    pi_dec: &[(&Integer, &[Integer])],
    i_aux: &[String],
) -> Result<VerifyDecryptionsResult, DecryptionError> {
    let upper_n = upper_cs.len();
    if upper_n == 0 {
        return Err(DecryptionError::NoCiphertext);
    }
    if upper_n != upper_cs_prime.len() {
        return Err(DecryptionError::CipherTextVectorsLenNotSame);
    }
    if upper_n != pi_dec.len() {
        return Err(DecryptionError::DecryptionProofLenNotSame);
    }
    let l = upper_cs[0].l();
    if upper_cs.iter().any(|c| c.l() != l) {
        return Err(DecryptionError::LNotConsistentOverCiphertexts { name: "C" });
    }
    if upper_cs_prime.iter().any(|c| c.l() != l) {
        return Err(DecryptionError::LNotConsistentOverCiphertexts { name: "C'" });
    }
    if pi_dec.iter().any(|pi| pi.1.len() != l) {
        return Err(DecryptionError::LNotConsistentOverCiphertexts { name: "pi_dec" });
    }
    Ok(VerifyDecryptionsResult::from(
        upper_cs
            .iter()
            .zip(upper_cs_prime.iter())
            .zip(pi_dec.iter())
            .map(|((c_i, c_prime_i), pi_i)| {
                let verif_gamma = c_i.gamma == c_prime_i.gamma;
                let m = c_prime_i.phis.as_slice();
                let verif_decryption = verify_decryption(ep, c_i, pks, m, i_aux, (pi_i.0, pi_i.1))?;
                Ok(VerifyDecryptionResultOneCiphertext {
                    verif_gamma,
                    verif_decryption,
                })
            })
            .collect::<Result<Vec<_>, DecryptionProofError>>()
            .map_err(DecryptionError::from)?
            .as_slice(),
    ))
}

impl VerifyDecryptionResultOneCiphertext {
    pub fn is_ok(&self) -> bool {
        self.verif_decryption && self.verif_gamma
    }
}

impl Display for VerifyDecryptionResultOneCiphertext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self.is_ok() {
                true => "Verification ok".to_string(),
                false => format!(
                    "verif_gamma: {} / verif_decryption: {}",
                    self.verif_gamma, self.verif_decryption
                ),
            }
        )
    }
}

impl VerifyDecryptionsResult {
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }
}

impl Display for VerifyDecryptionsResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self.is_ok() {
                true => "Verification ok".to_string(),
                false => {
                    let res_str = self
                        .errors
                        .iter()
                        .map(|(i, err)| format!("{i}: {{{err}}}"))
                        .collect::<Vec<_>>();
                    res_str.join(" / ")
                }
            }
        )
    }
}

impl From<&[VerifyDecryptionResultOneCiphertext]> for VerifyDecryptionsResult {
    fn from(value: &[VerifyDecryptionResultOneCiphertext]) -> Self {
        VerifyDecryptionsResult {
            errors: value
                .iter()
                .enumerate()
                .filter(|(_, err)| !err.is_ok())
                .map(|(i, err)| (i, *err))
                .collect::<Vec<_>>(),
        }
    }
}
