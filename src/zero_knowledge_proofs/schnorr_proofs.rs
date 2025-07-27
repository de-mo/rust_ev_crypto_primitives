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
use thiserror::Error;

#[derive(Error, Debug)]
#[error(transparent)]
/// Error during Schnorr proofs
pub struct SchnorrProofError(#[from] SchnorrProofErrorRepr);

#[derive(Error, Debug)]
enum PhiSchnorrError {
    #[error("Error calculating g^x mod p")]
    GExpXModP { source: ModExponentiateError },
}

#[derive(Error, Debug)]
enum SchnorrProofErrorRepr {
    #[error("Error checking the elgamal parameters")]
    CheckElgamal(Vec<EncryptionParameterDomainError>),
    #[error("Error Compute Phi Schnorr")]
    PhiSchnorrError {
        #[from]
        source: PhiSchnorrError,
    },

    #[error("y is not quadratic residue of p (in verify_schnorr)")]
    NotQudraticResidue(#[from] QuadraticResidueError),
    #[error("Error calculating y^e mod p")]
    YExpEModP { source: ModExponentiateError },
    #[error("Error in v^(-1) mod p claculting cs'")]
    InverseVModP { source: IntegerOperationError },
    #[error("Error hashing e'")]
    EPrimeHash { source: HashError },
}

/// Compute Phi Schnorr according to specifications of Swiss Post (Algorithm 10.1)
fn compute_phi_schnorr(ep: &EncryptionParameters, x: &Integer) -> Result<Integer, PhiSchnorrError> {
    ep.g()
        .mod_exponentiate(x, ep.p())
        .map_err(|e| PhiSchnorrError::GExpXModP { source: e })
}

/// Verify Schnorr Proof according to specifications of Swiss Post (Algorithm 10.3)
///
/// # Error
/// Return an error if preconditions are not satisfied
pub fn verify_schnorr(
    ep: &EncryptionParameters,
    (e, z): (&Integer, &Integer),
    y: &Integer,
    i_aux: &Vec<String>,
) -> Result<bool, SchnorrProofError> {
    verify_schnorr_impl(ep, (e, z), y, i_aux).map_err(SchnorrProofError::from)
}

fn verify_schnorr_impl(
    ep: &EncryptionParameters,
    (e, z): (&Integer, &Integer),
    y: &Integer,
    i_aux: &Vec<String>,
) -> Result<bool, SchnorrProofErrorRepr> {
    if cfg!(feature = "checks") {
        let domain_errs = ep.verifiy_domain();
        if !domain_errs.is_empty() {
            return Err(SchnorrProofErrorRepr::CheckElgamal(domain_errs));
        }
        y.result_is_quadratic_residue_unchecked(ep.p())
            .map_err(SchnorrProofErrorRepr::NotQudraticResidue)?;
    }
    let x = compute_phi_schnorr(ep, z).map_err(SchnorrProofErrorRepr::from)?;
    let f = HashableMessage::from(vec![ep.p(), ep.q(), ep.g()]);
    // e in Z_q => modulo q
    // x, y in G_q => modulo p
    let c_prime = x.mod_multiply(
        &y.mod_exponentiate(e, ep.p())
            .map_err(|e| SchnorrProofErrorRepr::YExpEModP { source: e })?
            .mod_inverse(ep.p())
            .map_err(|e| SchnorrProofErrorRepr::InverseVModP { source: e })?,
        ep.p(),
    );
    let mut l: Vec<HashableMessage> = vec![];
    l.push(HashableMessage::from("SchnorrProof"));
    if !i_aux.is_empty() {
        l.push(HashableMessage::from(i_aux.as_slice()));
    }
    let h_aux = HashableMessage::from(l);
    let l_final: Vec<HashableMessage> = vec![
        f,
        HashableMessage::from(y),
        HashableMessage::from(&c_prime),
        h_aux,
    ];
    let e_prime = HashableMessage::from(&l_final)
        .recursive_hash()
        .map_err(|e| SchnorrProofErrorRepr::EPrimeHash { source: e })?
        .into_integer();
    Ok(&e_prime == e)
}

#[cfg(test)]
mod test {
    use std::path::Path;

    use serde_json::Value;

    use crate::{
        test_json_data::{
            ep_from_json_value, json_64_value_to_integer, json_array_value_to_array_string,
        },
        zero_knowledge_proofs::test::{proof_from_json_values, Proof},
        Hexa,
    };

    use super::*;

    fn get_test_cases() -> Vec<Value> {
        let test_file = Path::new("./")
            .join("test_data")
            .join("zeroknowledgeproofs")
            .join("verify-schnorr.json");
        let json = std::fs::read_to_string(test_file).unwrap();
        serde_json::from_str(&json).unwrap()
    }

    struct Input {
        proof: Proof,
        statement: Integer,
        additional_information: Vec<String>,
    }

    fn get_input(input: &Value) -> Input {
        Input {
            proof: proof_from_json_values(&input["proof"]),
            statement: json_64_value_to_integer(&input["statement"]),
            additional_information: json_array_value_to_array_string(
                &input["additional_information"],
            ),
        }
    }

    #[test]
    fn test_verify_schnorr_check_wrong() {
        let p = Integer::from(13u8);
        let q=  Integer::from_hexa_string("0x5BF0A8B1457695355FB8AC404E7A79E3B1738B079C5A6D2B53C26C8228C867F799273B9C49367DF2FA5FC6C6C618EBB1ED0364055D88C2F5A7BE3DABABFACAC24867EA3EBE0CDDA10AC6CAAA7BDA35E76AAE26BCFEAF926B309E18E1C1CD16EFC54D13B5E7DFD0E43BE2B1426D5BCE6A6159949E9074F2F5781563056649F6C3A21152976591C7F772D5B56EC1AFE8D03A9E8547BC729BE95CADDBCEC6E57632160F4F91DC14DAE13C05F9C39BEFC5D98068099A50685EC322E5FD39D30B07FF1C9E2465DDE5030787FC763698DF5AE6776BF9785D84400B8B1DE306FA2D07658DE6944D8365DFF510D68470C23F9FB9BC6AB676CA3206B77869E9BDF34E8031").unwrap();
        let g = Integer::from_hexa_string("0x4").unwrap();
        let e = Integer::from_hexa_string(
            "0x29D551590009AC768A674AC0C42416FDDCF261DE93CA78ED53632929169406E1",
        )
        .unwrap();
        let z = Integer::from_hexa_string("0x4BC63F12E01FBE31246E7EF85292D8ABAAF850C9531E78B5EF7DE7692259E2DF5F0AC93A8BC7F262FA8ACCC5352C6B81976FB8A470FCB80696EFB46DF4EF9E86326AC801B692E4BCD0DAA452A2D749EEE277358EBA0C141187088DCF1CEF6DDAB8FEE47299671BF7AB411AF8E792787471B74DF3866187808685E2FF169AAC4AE55B6CA7152EB29BD82317F1BD26680C6BC15DA734E1E19153253A8D2AFA0C11B08B20A2D334EDE3D29460DA359306B4B7DD4DB65B3CE4F18FDEC6FBE5328C319C5847F8DC7B9FB97E997416CA58DCF286A3D8992B2453F4924152C34687579E1D3E8AACA94F24D24C2810C70AF14BD78BDF6F528BC8167364329685F7F5D60A").unwrap();
        let y = Integer::from_hexa_string("0x6AC7B188F3C0AB80238FEA40C71A3BA9C8E438F549CC113C1FA23B0893C0C63157C2E4E147CD69BAEBF2EB464F64131F99D7E23D939972D7E6E60FEF27068E34B84CF011129AF98B0F82C78859F890F6312652BD162477A23ACC3516B2945F52E3FE0168000B3F62B04823418F1B1D3D3BE030586B39174EB1BACB832FC8E86A151DFDC11106B484530B1F9F6E4E072EDFDED5E4C564D75978B05CB797256C225901F31DD2DE56709509BDAE1DFBECA410AEFC94D87A7D585012E70EA977A812744CFF03E50A7FD5B74B7BC232D2318A384E19C0BBAA5D1100DFFD903B9FDE5D86DCDF6541444AA8983F297F9C94E50D2273B020881A600CA5B0FBCB9A17ACD3").unwrap();
        let add_info: Vec<String> = vec!["test-0".to_string()];
        if cfg!(feature = "checks") {
            assert!(verify_schnorr(
                &EncryptionParameters::from((&p, &q, &g)),
                (&e, &z),
                &y,
                &add_info
            )
            .is_err())
        } else {
            assert!(verify_schnorr(
                &EncryptionParameters::from((&p, &q, &g)),
                (&e, &z),
                &y,
                &add_info
            )
            .is_ok())
        }
    }

    #[test]
    fn test_verify() {
        for tc in get_test_cases() {
            let ep = ep_from_json_value(&tc["context"]);
            let input = get_input(&tc["input"]);
            assert!(
                verify_schnorr(
                    &ep,
                    (&input.proof.e, &input.proof.z),
                    &input.statement,
                    &input.additional_information
                )
                .unwrap(),
                "{}",
                &tc["description"]
            )
        }
    }
}
