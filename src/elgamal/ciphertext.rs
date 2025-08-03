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

//! Implementation of the ciphertext operations

use super::{ElgamalError, ElgamalErrorRepr, EncryptionParameters};
use crate::{
    integer::ModExponentiateError, ConstantsTrait, HashableMessage, Integer, OperationsTrait,
};
use std::{iter::once, ops::ControlFlow};
use thiserror::Error;

#[derive(Error, Debug)]
pub(super) enum CiphertextError {
    #[error("get_ciphertext: l must be between 1 and k={k}, but is {l}")]
    LNotCorrect { l: usize, k: usize },
    #[error("get_ciphertext: error calculating gamma")]
    Gamma { source: ModExponentiateError },
    #[error("get_ciphertext: error calculating the array phi")]
    Phis { source: ModExponentiateError },
    #[error("get_ciphertext_exponentiation: error calculating gamma")]
    GammaExp { source: ModExponentiateError },
    #[error("get_ciphertext_exponentiation: error calculating the array phi")]
    PhisExp { source: ModExponentiateError },
    #[error("get_ciphertext_vector_exponentiation: error during calculation")]
    VecExp { source: Box<ElgamalError> },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ciphertext {
    pub gamma: Integer,
    pub phis: Vec<Integer>,
}

impl Ciphertext {
    pub fn from_expanded(gamma: &Integer, phis: &[Integer]) -> Self {
        Self {
            gamma: gamma.clone(),
            phis: phis.to_vec(),
        }
    }

    pub fn l(&self) -> usize {
        self.phis.len()
    }

    pub fn neutral_for_mod_multiply(l: usize) -> Self {
        Self::from_expanded(Integer::one(), vec![Integer::one().clone(); l].as_slice())
    }

    /// Algorithm 8.5 GetCiphertext
    pub fn get_ciphertext(
        ep: &EncryptionParameters,
        ms: &[Integer],
        r: &Integer,
        pks: &[Integer],
    ) -> Result<Self, ElgamalError> {
        Self::get_ciphertext_impl(ep, ms, r, pks)
            .map_err(ElgamalErrorRepr::Ciphertext)
            .map_err(ElgamalError::from)
    }

    fn get_ciphertext_impl(
        ep: &EncryptionParameters,
        ms: &[Integer],
        r: &Integer,
        pks: &[Integer],
    ) -> Result<Self, CiphertextError> {
        let l = ms.len();
        let k = pks.len();
        let p = ep.p();
        if l == 0 && l > k {
            return Err(CiphertextError::LNotCorrect { l, k });
        }
        let gamma = ep
            .g()
            .mod_exponentiate(r, p)
            .map_err(|e| CiphertextError::Gamma { source: e })?;
        let phis = ms
            .iter()
            .zip(pks.iter())
            .map(|(m, pk)| {
                pk.mod_exponentiate(r, p)
                    .map(|v| v.mod_multiply(m, p))
                    .map_err(|e| CiphertextError::Phis { source: e })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { gamma, phis })
    }

    /// Algorithm 8.6 GetCiphertextExponentiation
    pub fn get_ciphertext_exponentiation(
        &self,
        a: &Integer,
        ep: &EncryptionParameters,
    ) -> Result<Self, ElgamalError> {
        self.get_ciphertext_exponentiation_impl(a, ep)
            .map_err(ElgamalErrorRepr::Ciphertext)
            .map_err(ElgamalError::from)
    }

    fn get_ciphertext_exponentiation_impl(
        &self,
        a: &Integer,
        ep: &EncryptionParameters,
    ) -> Result<Self, CiphertextError> {
        let p = ep.p();
        let gamma = self
            .gamma
            .mod_exponentiate(a, p)
            .map_err(|e| CiphertextError::GammaExp { source: e })?;
        let phis = self
            .phis
            .iter()
            .map(|phi| {
                phi.mod_exponentiate(a, p)
                    .map_err(|e| CiphertextError::PhisExp { source: e })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { gamma, phis })
    }

    /// Algorithm 8.8 GetCiphertextProduct
    pub fn get_ciphertext_product(&self, other: &Self, ep: &EncryptionParameters) -> Self {
        let p = ep.p();
        let gamma = self.gamma.mod_multiply(&other.gamma, p);
        let phis: Vec<Integer> = self
            .phis
            .iter()
            .zip(other.phis.iter())
            .map(|(phi_a, phi_b)| phi_a.mod_multiply(phi_b, p))
            .collect();
        Self { gamma, phis }
    }

    /// Algorithm 8.7 GetCiphertextVectorExponentiation
    pub fn get_ciphertext_vector_exponentiation(
        cs: &[Ciphertext],
        a: &[Integer],
        ep: &EncryptionParameters,
    ) -> Result<Self, ElgamalError> {
        let ones_cipher = Self::from(vec![Integer::one().clone(); cs[0].l() + 1].as_slice());
        match cs
            .iter()
            .zip(a.iter())
            .map(|(c, a)| c.get_ciphertext_exponentiation(a, ep))
            .try_fold(ones_cipher, |acc, c_res| match c_res {
                Ok(c) => ControlFlow::Continue(acc.get_ciphertext_product(&c, ep)),
                Err(e) => ControlFlow::Break(e),
            }) {
            ControlFlow::Continue(v) => Ok(v),
            ControlFlow::Break(e) => Err(ElgamalError::from(ElgamalErrorRepr::from(
                CiphertextError::VecExp {
                    source: Box::new(e),
                },
            ))),
        }
    }
}

impl<'a> From<&'a Ciphertext> for HashableMessage<'a> {
    fn from(value: &'a Ciphertext) -> Self {
        HashableMessage::from(
            once(&value.gamma)
                .chain(value.phis.iter())
                .map(HashableMessage::from)
                .collect::<Vec<HashableMessage<'a>>>(),
        )
    }
}

impl<'a> From<Ciphertext> for HashableMessage<'a> {
    fn from(value: Ciphertext) -> Self {
        HashableMessage::from(
            once(value.gamma.clone())
                .chain(value.phis)
                .map(HashableMessage::from)
                .collect::<Vec<HashableMessage<'a>>>(),
        )
    }
}

impl<'a> From<&'a Vec<Ciphertext>> for HashableMessage<'a> {
    fn from(value: &'a Vec<Ciphertext>) -> Self {
        HashableMessage::from(
            value
                .iter()
                .map(HashableMessage::from)
                .collect::<Vec<HashableMessage<'a>>>(),
        )
    }
}

impl<'a> From<&'a [Ciphertext]> for HashableMessage<'a> {
    fn from(value: &'a [Ciphertext]) -> Self {
        HashableMessage::from(
            value
                .iter()
                .map(HashableMessage::from)
                .collect::<Vec<HashableMessage<'a>>>(),
        )
    }
}

impl<'a> From<Vec<Ciphertext>> for HashableMessage<'a> {
    fn from(value: Vec<Ciphertext>) -> Self {
        HashableMessage::from(
            value
                .iter()
                .map(|e| HashableMessage::from(e.clone()))
                .collect::<Vec<HashableMessage<'a>>>(),
        )
    }
}

impl<'a> From<&'a Vec<&'a Ciphertext>> for HashableMessage<'a> {
    fn from(value: &'a Vec<&'a Ciphertext>) -> Self {
        HashableMessage::from(
            value
                .iter()
                .map(|&c| HashableMessage::from(c))
                .collect::<Vec<HashableMessage<'a>>>(),
        )
    }
}

impl<'a> From<Vec<&'a Ciphertext>> for HashableMessage<'a> {
    fn from(value: Vec<&'a Ciphertext>) -> Self {
        HashableMessage::from(
            value
                .iter()
                .map(|&c| HashableMessage::from(c))
                .collect::<Vec<HashableMessage<'a>>>(),
        )
    }
}

impl From<&[Integer]> for Ciphertext {
    fn from(value: &[Integer]) -> Self {
        Self {
            gamma: value[0].clone(),
            phis: value.iter().skip(1).cloned().collect(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        test_json_data::{
            json_value_to_encryption_parameters, json_values_to_ciphertext_values, get_test_cases_from_json_file, json_64_value_to_integer,
            json_array_64_value_to_array_integer, CiphertextValues,
        },
        Hexa,
    };
    use serde_json::Value;

    struct InputsGetCiphertext {
        bold_m: Vec<Integer>,
        r: Integer,
        bold_pk: Vec<Integer>,
    }

    struct InputsGetCiphertextProduct {
        upper_c_a: CiphertextValues,
        upper_c_b: CiphertextValues,
    }

    fn get_input_get_ciphertext(input: &Value) -> InputsGetCiphertext {
        InputsGetCiphertext {
            bold_m: json_array_64_value_to_array_integer(&input["bold_m"]),
            r: json_64_value_to_integer(&input["r"]),
            bold_pk: json_array_64_value_to_array_integer(&input["bold_pk"]),
        }
    }

    fn get_input_get_ciphertext_product(input: &Value) -> InputsGetCiphertextProduct {
        InputsGetCiphertextProduct {
            upper_c_a: json_values_to_ciphertext_values(&input["upper_c_a"]),
            upper_c_b: json_values_to_ciphertext_values(&input["upper_c_b"]),
        }
    }

    #[test]
    fn test_get_cyphertext() {
        for tc in get_test_cases_from_json_file("elgamal", "get-ciphertext.json") {
            let ep = json_value_to_encryption_parameters(&tc["context"]);
            let input = get_input_get_ciphertext(&tc["input"]);
            let output = json_values_to_ciphertext_values(&tc["output"]);
            let c_res = Ciphertext::get_ciphertext(&ep, &input.bold_m, &input.r, &input.bold_pk);
            assert!(c_res.is_ok());
            let c = c_res.unwrap();
            assert_eq!(
                c.gamma, output.gamma,
                "Not same gamma for {}",
                tc["description"]
            );
            assert_eq!(
                c.phis, output.phis,
                "Not same phis for {}",
                tc["description"]
            )
        }
    }

    #[test]
    fn test_get_cyphertext_product() {
        for tc in get_test_cases_from_json_file("elgamal", "get-ciphertext-product.json") {
            let ep = json_value_to_encryption_parameters(&tc["context"]);
            let input = get_input_get_ciphertext_product(&tc["input"]);
            let output = json_values_to_ciphertext_values(&tc["output"]);
            let res = (Ciphertext {
                gamma: input.upper_c_a.gamma,
                phis: input.upper_c_a.phis,
            })
            .get_ciphertext_product(
                &(Ciphertext {
                    gamma: input.upper_c_b.gamma,
                    phis: input.upper_c_b.phis,
                }),
                &ep,
            );
            assert_eq!(
                res.gamma, output.gamma,
                "Not same gamma for {}",
                tc["description"]
            );
            assert_eq!(
                res.phis, output.phis,
                "Not same phis for {}",
                tc["description"]
            )
        }
    }

    #[test]
    fn test_neutral_ciphertext() {
        let p = Integer::from_hexa_string(
            "0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF324E7738926CFBE5F4BF8D8D8C31D763DA06C80ABB1185EB4F7C7B5757F5958490CFD47D7C19BB42158D9554F7B46BCED55C4D79FD5F24D6613C31C3839A2DDF8A9A276BCFBFA1C877C56284DAB79CD4C2B3293D20E9E5EAF02AC60ACC93ED874422A52ECB238FEEE5AB6ADD835FD1A0753D0A8F78E537D2B95BB79D8DCAEC642C1E9F23B829B5C2780BF38737DF8BB300D01334A0D0BD8645CBFA73A6160FFE393C48CBBBCA060F0FF8EC6D31BEB5CCEED7F2F0BB088017163BC60DF45A0ECB1BCD289B06CBBFEA21AD08E1847F3F7378D56CED94640D6EF0D3D37BE67008E186D1BF275B9B241DEB64749A47DFDFB96632C3EB061B6472BBF84C26144E49C2D04C324EF10DE513D3F5114B8B5D374D93CB8879C7D52FFD72BA0AAE7277DA7BA1B4AF1488D8E836AF14865E6C37AB6876FE690B571121382AF341AFE94F77BCF06C83B8FF5675F0979074AD9A787BC5B9BD4B0C5937D3EDE4C3A79396419CD7"
        ).unwrap();
        let q = Integer::from_hexa_string(
            "0x5BF0A8B1457695355FB8AC404E7A79E3B1738B079C5A6D2B53C26C8228C867F799273B9C49367DF2FA5FC6C6C618EBB1ED0364055D88C2F5A7BE3DABABFACAC24867EA3EBE0CDDA10AC6CAAA7BDA35E76AAE26BCFEAF926B309E18E1C1CD16EFC54D13B5E7DFD0E43BE2B1426D5BCE6A6159949E9074F2F5781563056649F6C3A21152976591C7F772D5B56EC1AFE8D03A9E8547BC729BE95CADDBCEC6E57632160F4F91DC14DAE13C05F9C39BEFC5D98068099A50685EC322E5FD39D30B07FF1C9E2465DDE5030787FC763698DF5AE6776BF9785D84400B8B1DE306FA2D07658DE6944D8365DFF510D68470C23F9FB9BC6AB676CA3206B77869E9BDF3380470C368DF93ADCD920EF5B23A4D23EFEFDCB31961F5830DB2395DFC26130A2724E1682619277886F289E9FA88A5C5AE9BA6C9E5C43CE3EA97FEB95D0557393BED3DD0DA578A446C741B578A432F361BD5B43B7F3485AB88909C1579A0D7F4A7BBDE783641DC7FAB3AF84BC83A56CD3C3DE2DCDEA5862C9BE9F6F261D3C9CB20CE6B"
        ).unwrap();
        let g = Integer::from(4u8);
        let ep = EncryptionParameters::from((&p, &q, &g));
        let gamma = Integer::from_hexa_string(
            "0x113834A47977101D4ECD962B8163E03B5285AF19A60A8008C234A01A8C716C8F42830B8772B70FC6F961C71AD2508D41D613DD8F402F3A532256B29EEC33E94BEBDAEF525ED8C67BE43D0B4D131A8E7DCA831C0652A9B00B26C7E8CAC1E7C120243538194286AEABCF434C6069E5B69B99AE25CF3CFC04E76F3291549B700B371C6771EC89498B5E94CAAFA84C3BD7B61F978B47A66C678BA0716F3D235DB061E35967AB7DC2A6A8F897AC58DCD1A21E9E22AD8838AFF98716CE45B0BD1BBDA2857944BD49A22ACF65F581E36844021C4F9410D0F4C4FEE0D8389C65FE2309B5EFD879913504062ACB778C530C3F51CE96D9159D972869B1083DFD552B1E9432B4067699946D68CCBE83E8B7CF52E3CF275DE579E8A065AB192BE04ACE6B94B41574967E37F081C678FD98076687BDBE841FB7AEFD5C67B875335AFF37FD6FDC5F862F7B8165761AEFD0C57E29D163DFD71E1335E17C9B8112B66D7FCC511E29B29D2E513FE32CB03C5F03286CF45EAD4D2153491415B86C5DADE0F95980323F"
        ).unwrap();
        let phis: Vec<Integer> = [
            "0x9624FEF18E71381727D2B3212BA5EC4B1A15F94061293CC6E7536E4D3B6A996BD4A00BCD8F6BA389CD77CFE1A4F8E1CCDDAF934BF6DD6CCD56ACAB248835A601490201D101B7CB038631A791C5BB9E8CC9B5C0A41ECDC41D8BF1BE154AA658AF70DB77F9E5284B0EE9639A7DF180E618C484BA7966961A2232CF13B755F01ABEFB24B85FD158D4BF7761B5BE9E5653820EC0694FFCC2BD31D08D4022D054DC67EA1656472835CD6CF73F88E3F3A245F414E5868368F5FF21FA88E4B9839D3E7F38B16780A2C60A21608AB5E2EC34D91EA74610B6A6DD1708E527AA536EE9003420C8514AA799F2876F0A70CE51DDB46986A22D191BE7C0471E5C96020BB9A9F2602B7A470EE0063922E59F86B7EB1C188A2A3DE4969B92E10D84D6A260AE57DD8FB4D8BB0FFADCC88F7B1038614D38E1A50048E1E47F7F2E097034568641321F1C1963E5AA62074A34731DDD38EFC93425F3F17941B594B053DF6C676A7ECBF0ABB1F95758997FE962F7F0445A45CD39793F043303328D1B5A9FB5B9C056412A",
            "0xC2706D74BE479E61F6968D9F1B189CA77802CC5AEE1F8CE2311465215BA779DB929D6FD4C040B846FF3DAD3A969207F20AA2BEDC73D9061C45FCBDDA74741803642563DD9F0E20084AF29270208123583A1D6B318EA70501B687535407DEA931B96713E4F7EE5DA9F99398E12F581F363E9252438DFEC0348C551E587731650B8A95D5EF8BE2238F0C091186F34A939E38F5FD062E7592AA325448846B65E4DC4E5A0490BC9E2594536D1FDF97DD88B71E1F5503E20089A91DB5BF82AEEDEF1F456BB20442BB8DBBF52FB6EC662349FD8E1D0652199CADB7D5BF69626678A2CD809FA2E4E74879DEB8C9B3BFC7EDCE1472F8108C9F8DC0C66CEFEA8CD11DF7CEF097B20EC384ACD6B00F4ABDBE5D3ABB01752112E20C56210D74068D94F05D81A333E75C90D3E662189DCF4BA9E9C5CA72E4474461AF70E6459EC8B7C46AB2657DBCE5824720938B76E2CEBC286B7EDF9F2251A7D72095ABD4955DBCB360FA38BA49FAF5CD63C34714130662B2E4ECA0C529C62AE6782369371AFAB082F7B97",
        ]
            .iter()
            .map(|s| Integer::from_hexa_string(s).unwrap())
            .collect();
        let ciphertext = Ciphertext { gamma, phis };
        let one = Ciphertext::neutral_for_mod_multiply(ciphertext.l());
        let mult_a = ciphertext.get_ciphertext_product(&one, &ep);
        let mult_b = one.get_ciphertext_product(&ciphertext, &ep);
        assert_eq!(mult_a.gamma, ciphertext.gamma);
        assert_eq!(mult_a.phis, ciphertext.phis);
        assert_eq!(mult_b.gamma, ciphertext.gamma);
        assert_eq!(mult_b.phis, ciphertext.phis);
    }
}
