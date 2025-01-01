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

use thiserror::Error;

use crate::{
    elgamal::EncryptionParameters, ConstantsTrait, HashError, HashableMessage, Integer,
    IntegerError, OperationsTrait, RecursiveHashTrait,
};

use super::matrix::{Matrix, MatrixError};

/// Structure for the verifiable commitment key according specification of swiss post
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentKey {
    pub h: Integer,
    pub gs: Vec<Integer>,
}

#[derive(Error, Debug)]
pub enum CommitmentError {
    #[error("nu too big. Must less or equal q-3.")]
    NuTooBig,
    #[error(transparent)]
    HashError(#[from] HashError),
    #[error(transparent)]
    MatrixError(#[from] MatrixError),
    #[error(transparent)]
    IntegerError(#[from] IntegerError),
    #[error("Matrix is mallformed in: {0}")]
    MalformedMatrix(String),
    #[error("Size {0} of random vector must be {1}")]
    RandomSizeWrong(usize, usize),
    #[error("Size of commitment key to small")]
    SmallCommitmentKey,
}

impl CommitmentKey {
    /// GetVerifiableCommitmentKey (algorithnm 9.6)
    pub fn get_verifiable_commitment_key(
        ep: &EncryptionParameters,
        nu: usize,
    ) -> Result<Self, CommitmentError> {
        if nu > Integer::from(ep.q() - 3) {
            return Err(CommitmentError::NuTooBig);
        }
        let mut count = 0;
        let mut i = 0;
        let mut v = vec![];
        while count <= nu {
            let u = HashableMessage::from(vec![
                HashableMessage::from("commitmentKey"),
                HashableMessage::from(&i),
                HashableMessage::from(&count),
            ])
            .recursive_hash_to_zq(ep.q())
            .map_err(CommitmentError::HashError)?
                + Integer::one();
            let w = u.mod_square(ep.p())?;
            if &w != Integer::one() && &w != ep.g() && !v.contains(&w) {
                v.push(w);
                count += 1;
            }
            i += 1;
        }
        let gs = v.drain(1..).collect();
        let h = v[0].clone();
        Ok(Self { h, gs })
    }

    /// nu: size of the vector gs
    pub fn nu(&self) -> usize {
        self.gs.len()
    }

    /// Structur to vector, putting `h` before `g`
    pub fn to_vec(&self) -> Vec<Integer> {
        let mut res: Vec<Integer> = self.gs.clone();
        res.insert(0, self.h.clone());
        res
    }
}

impl<'a> From<&'a CommitmentKey> for HashableMessage<'a> {
    fn from(value: &'a CommitmentKey) -> Self {
        let mut res: Vec<HashableMessage> = value.gs.iter().map(HashableMessage::from).collect();
        res.insert(0, HashableMessage::from(&value.h));
        HashableMessage::from(res)
    }
}

pub fn get_commitment(
    ep: &EncryptionParameters,
    a: &[Integer],
    r: &Integer,
    ck: &CommitmentKey,
) -> Result<Integer, CommitmentError> {
    if ck.gs.len() < a.len() {
        return Err(CommitmentError::SmallCommitmentKey);
    }
    let prod = Integer::mod_multi_exponentiate(&ck.gs, a, ep.p())?;
    println!("prod of get_commitment = {}", &prod);
    let c =
        ck.h.mod_exponentiate(r, ep.p())
            .map_err(CommitmentError::IntegerError)?
            .mod_multiply(&prod, ep.p());
    Ok(c)
}

pub fn get_commitment_matrix(
    ep: &EncryptionParameters,
    a: &Matrix<Integer>,
    rs: &[Integer],
    ck: &CommitmentKey,
) -> Result<Vec<Integer>, CommitmentError> {
    if a.is_malformed() {
        return Err(CommitmentError::MalformedMatrix(
            "get_commitment_matrix".to_string(),
        ));
    }
    if a.nb_columns() != rs.len() {
        return Err(CommitmentError::RandomSizeWrong(rs.len(), a.nb_columns()));
    }
    a.columns_cloned_iter()
        .zip(rs.iter())
        .map(|(a_i, r_i)| get_commitment(ep, &a_i, r_i, ck))
        .collect::<Result<Vec<Integer>, CommitmentError>>()
}

#[allow(dead_code)]
pub fn get_commitment_vector(
    ep: &EncryptionParameters,
    ds: &[Integer],
    ts: &[Integer],
    ck: &CommitmentKey,
) -> Result<Vec<Integer>, CommitmentError> {
    let a = Matrix::to_matrix(ds, (1, ds.len())).map_err(CommitmentError::MatrixError)?;
    get_commitment_matrix(ep, &a, ts, ck)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        test_json_data::{json_array_value_to_array_mpinteger, json_value_to_mpinteger},
        Hexa,
    };
    use serde_json::Value;
    use std::path::Path;

    #[test]
    fn test_recursive_hash() {
        let ck = CommitmentKey {
            h: Integer::from_hexa_string(
                "0x7C3B68684EB1670CA19A45722B6F0DE570E8CE25DBB6C85E6612884C6C44B1C98B0BE3395B9CB3503F68E24DAF676F05EAF7C1C4D92257A58288D4903BB5987A537DCB005758AB6FAEB9612412E17042E1971E5C5E6C3C4363E3D8DDC3435756992762C7E4BE0E19A231570697A3785E8DCC48637F1D98BC2C2482A05189C21DF9529D7EE39D8FB1249BD05F3018B0019DFEE6EE7EBAA2308CA96B893B620F6719ECAA0BDCDF8A2F39E8A8D2AFF75A41FAAF5C425D0ECD121B4C3B248430C96D72F0457E0DA46E5797724B00F14609D59359BC3CC8D77E0B2773CC4A4F4DE39216534D69D5D74980839322ED8A9D99BF78BE563B2F93B2BF41427EABBEB2A6AE2294B2C949A04EA2FC8AF14CBB639ECF98A1AB04B1A689564038A67B6B726C18B0F6EF205A3D48B816EC5FB1C6815528DB759074DEFF3EFD96735AAF4951FC18A8AC11EBAA05AC2D826640FCCF93DF578B573848ECC6ADB3C691ABB2D878751FA550198EFA4F5034701A7A667D4C8EACFD9AD311071D87EF8E99B4A2583D84C8"
            ).unwrap(),
            gs: [
                "0x898963C17A657A324B26F3DFAA7BDBAB2975756DCF642F8274B6EB777AE48F87D14F76EFFE24FF8020EFF39D8D552598DDF85A7FC7D58053B1793D73F14AE876D0A8D06044588D3047C0E37B769D42D9897287C78D50E5B77ED8AA77048B30C0029512F64850316C80D69564846EAB1C1A13E5B3812DD46DA1D8AC20FD3B41F240257BBC7F66930F536D5099E1F8D67E300CDA1013308267A70EBCE95C349EF6CC74DB60FDD3901E33CB60CE31E122E661CD141B32F3A0242C64D342063439F3B5B192A75AD53146198D567C4B008D8185601A9C22E577DB2433103556E07C0ADB8EDDDDF3A45B6BC9FE022BC49EFC9B49490A69D87DE4B2AF03C90933FC25DDC61D6808101C93BF2665702479C4FF0EFB771A400ADAB49392CCC5CA210CC729C47A2EFDB0152ADD43D0291E42B8703D50C983C4E26AC0A9E8906E7A7D595B49B7C5A6C9114278BDDA90AC06202220E77E50DADC6B4961B170651E83988B59E0B9EE859FEE6EE11FD38C63EE96E2F21A613332171FF34EBE0261D8534FDC3C14",
                "0x2AB61BA8120F77DB556FB02543109D64F0D1B0468DC350C3EA4CECA0764E0F6C5F6E233AC4B3F58FB57D5B2AD23EF71694F6152D04BA8E107C1E5E3EC07E78FC78FB37970194BC66FD5D1A0A4D86EEE5A8DA50AB3C734FAB7ED89104381CCC31ECCF4DCC42548AB7D1134F244717661C29AB363C410D6A83421B98589A24884A2C12B84AFDE75E9F8B6CD88B23AC571770185C3866464CDC00DC2D418889E42C455226709FD93B1C75E58C623C7A45023B18C8841CCFEB7AF874D5E2F8131D832BDEB98622FB8DAD444F616CC236863B3A951999788ED98819D4F61E0FF495C13A3FEA7304428D41CA17B6ADC0B81CDB59EDB642F645A1AAC171A48C134E868200123B0F5F4088066751AE37D9116A8E5152FDAF6AC1E44E50B95985DE42DC564110D388CC02F38BDAE5AEECAED3DC5DF718F700B0DA39D708AEA3A50C751BCBEB740222C7620F3A5EDEFD6606D05DDF7A073FDA93545DA2F96E227AD61075C24E66BB043DFB9F268D1FA760792814BB2AB45EC312E5303358203A7A7499A24B",
            ]
                .iter()
                .map(|v| Integer::from_hexa_string(v).unwrap())
                .collect(),
        };
        let h = &ck.h;
        let gs_1 = &ck.gs[0];
        let gs_2 = &ck.gs[1];
        let expected = HashableMessage::from(vec![
            HashableMessage::from(h),
            HashableMessage::from(gs_1),
            HashableMessage::from(gs_2),
        ])
        .recursive_hash()
        .unwrap();
        assert_eq!(
            HashableMessage::from(&ck).recursive_hash().unwrap(),
            expected
        );
    }

    fn get_verif_commitment_key_test_cases() -> Vec<Value> {
        let test_file = Path::new("./")
            .join("test_data")
            .join("mixnet")
            .join("get-verifiable-commitment-key.json");
        let json = std::fs::read_to_string(test_file).unwrap();
        serde_json::from_str(&json).unwrap()
    }

    fn get_verif_commitment_key_ep(value: &Value) -> EncryptionParameters {
        EncryptionParameters::from((
            &json_value_to_mpinteger(&value["p"]),
            &json_value_to_mpinteger(&value["q"]),
            &json_value_to_mpinteger(&value["g"]),
        ))
    }

    fn get_expected(value: &Value) -> CommitmentKey {
        CommitmentKey {
            h: json_value_to_mpinteger(&value["h"]),
            gs: json_array_value_to_array_mpinteger(&value["g"]),
        }
    }

    #[test]
    fn test_verifiable_commitment_key() {
        for tc in get_verif_commitment_key_test_cases().iter() {
            let description = tc["description"].as_str().unwrap();
            let ep = get_verif_commitment_key_ep(&tc["context"]);
            let k = tc["input"]["k"].as_number().unwrap().as_u64().unwrap() as usize;
            let expected = get_expected(&tc["output"]);
            let r = CommitmentKey::get_verifiable_commitment_key(&ep, k);
            assert!(r.is_ok(), "{}", description);
            assert_eq!(r.unwrap(), expected, "{}", description);
        }
    }
}
