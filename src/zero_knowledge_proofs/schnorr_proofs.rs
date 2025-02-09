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
    number_theory::{NumberTheoryError, NumberTheoryMethodTrait},
    HashError, HashableMessage, Integer, IntegerError, OperationsTrait, RecursiveHashTrait,
    VerifyDomainTrait,
};
use thiserror::Error;

// Enum representing the errors in zero knowledge proofs
#[derive(Error, Debug)]
pub enum SchnorrProofError {
    #[error(transparent)]
    CheckNumberTheory(#[from] NumberTheoryError),
    #[error("Error checking the elgamal parameters")]
    CheckElgamal(Vec<EncryptionParameterDomainError>),
    #[error(transparent)]
    HashError(#[from] HashError),
    #[error(transparent)]
    IntegerError(#[from] IntegerError),
}

/// Compute Phi Schnorr according to specifications of Swiss Post (Algorithm 10.1)
fn compute_phi_schnorr(
    ep: &EncryptionParameters,
    x: &Integer,
) -> Result<Integer, SchnorrProofError> {
    ep.g()
        .mod_exponentiate(x, ep.p())
        .map_err(SchnorrProofError::IntegerError)
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
    if cfg!(feature = "checks") {
        let domain_errs = ep.verifiy_domain();
        if !domain_errs.is_empty() {
            return Err(SchnorrProofError::CheckElgamal(domain_errs));
        }
        y.result_is_quadratic_residue_unchecked(ep.p())
            .map_err(SchnorrProofError::CheckNumberTheory)?;
    }
    let x = compute_phi_schnorr(ep, z)?;
    let f = HashableMessage::from(vec![ep.p(), ep.q(), ep.g()]);
    // e in Z_q => modulo q
    // x, y in G_q => modulo p
    let c_prime = x.mod_multiply(&y.mod_exponentiate(e, ep.p())?.mod_inverse(ep.p())?, ep.p());
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
        .map_err(SchnorrProofError::HashError)?
        .into_integer();
    Ok(&e_prime == e)
}

#[cfg(test)]
mod test {
    use crate::Hexa;

    use super::*;

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
    fn test_verify_schnorr_3072() {
        let p = Integer::from_hexa_string("0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF324E7738926CFBE5F4BF8D8D8C31D763DA06C80ABB1185EB4F7C7B5757F5958490CFD47D7C19BB42158D9554F7B46BCED55C4D79FD5F24D6613C31C3839A2DDF8A9A276BCFBFA1C877C56284DAB79CD4C2B3293D20E9E5EAF02AC60ACC93ED874422A52ECB238FEEE5AB6ADD835FD1A0753D0A8F78E537D2B95BB79D8DCAEC642C1E9F23B829B5C2780BF38737DF8BB300D01334A0D0BD8645CBFA73A6160FFE393C48CBBBCA060F0FF8EC6D31BEB5CCEED7F2F0BB088017163BC60DF45A0ECB1BCD289B06CBBFEA21AD08E1847F3F7378D56CED94640D6EF0D3D37BE67008E186D1BF275B9B241DEB64749A47DFDFB96632C3EB061B6472BBF84C26144E49C2D04C324EF10DE513D3F5114B8B5D374D93CB8879C7D52FFD72BA0AAE7277DA7BA1B4AF1488D8E836AF14865E6C37AB6876FE690B571121382AF341AFE94F77BCF06C83B8FF5675F0979074AD9A787BC5B9BD4B0C5937D3EDE4C3A79396419CD7").unwrap();
        let q = Integer::from_hexa_string("0x5BF0A8B1457695355FB8AC404E7A79E3B1738B079C5A6D2B53C26C8228C867F799273B9C49367DF2FA5FC6C6C618EBB1ED0364055D88C2F5A7BE3DABABFACAC24867EA3EBE0CDDA10AC6CAAA7BDA35E76AAE26BCFEAF926B309E18E1C1CD16EFC54D13B5E7DFD0E43BE2B1426D5BCE6A6159949E9074F2F5781563056649F6C3A21152976591C7F772D5B56EC1AFE8D03A9E8547BC729BE95CADDBCEC6E57632160F4F91DC14DAE13C05F9C39BEFC5D98068099A50685EC322E5FD39D30B07FF1C9E2465DDE5030787FC763698DF5AE6776BF9785D84400B8B1DE306FA2D07658DE6944D8365DFF510D68470C23F9FB9BC6AB676CA3206B77869E9BDF3380470C368DF93ADCD920EF5B23A4D23EFEFDCB31961F5830DB2395DFC26130A2724E1682619277886F289E9FA88A5C5AE9BA6C9E5C43CE3EA97FEB95D0557393BED3DD0DA578A446C741B578A432F361BD5B43B7F3485AB88909C1579A0D7F4A7BBDE783641DC7FAB3AF84BC83A56CD3C3DE2DCDEA5862C9BE9F6F261D3C9CB20CE6B").unwrap();
        let g = Integer::from_hexa_string("0x4").unwrap();
        let e = Integer::from_hexa_string(
            "0xFE6B909E2C4EC3C9A25315EAF1E99A50452BBD22E75A69C247147E23669D665F",
        )
        .unwrap();
        let z = Integer::from_hexa_string("0x366D1E918E19C0B22D2393C88DBA28A4271CA9A030A528A42045FAC3E04F6C96A56593D9A1832BDB42FEE45C49588AD3CA071F83F13A5B03F43912D77746A72A76A2FB9E9FE802ACA107B357BC62A9076830D9DBD03B11AF028DAC5D36C3729E5D82CB83B4409E83B236CB61B3D4B79FF50CBB4FDFCD11DC78632ADC80D0F4FF3338E142C3C315764BD16F0378886D6A640D43257611FA8925D179B4156912B2737C4F96462EAE7B5F5A2AA19A7488B11151CBB13484FD6219632CF960D36C14157454F436D25C6D4289123D80100A8835608B67C8EC81CB311227F6FB5AF90EF5C69EB2687833E4E7FD60736A481365C68300EE74B770F22A63DADFDA5CB8DB9E05903F465DE906A59164D19A7F0B1D69DD8C9BE40E386143413C69993E4A5AAD966EB8DEAECFFE2E164EDB503518AECA71198CEDCAE50C2E95158CA53FE1D2FF26A4A04330A5152233E4DB78C39C56F55C361B38242645AB4D74E960221AE637239F149C61E9E51012D10BD2B7BBDC7B7696FE5C707DE668C5A71C17D83085").unwrap();
        let y = Integer::from_hexa_string("0x4D14E2B0ADB377E998C39DE477A96B74FD08E9E52BB6CF27717FADDBA2FCC5F3F65C9E99E4E33AAD0E1BC5A4E6429C805FC2FA0E5FF2C13A1C3B190B7156E7DF251C65E1229D13039751A881D99DB15D0E25118134CE37EF9EAEC921243F99AAD5CDE7834951F38E0DA9FD379252FD98EFAD7F040D690E4EB5E40296F7E76E1EFBB8037FF691BB891A2F9E78C83E806B6F0CF8B8E94C8401E87C29D2242D708AFCCB687380A07CC7A73C87F56FDDC6DD805E187D9A7C0B6D1D954FD875B5F331B33839BDAF3006417A9F8D197293BEF54B425C7A846793913B71208546A801FCBCD288BC4F9C228235CB8C243138A3F821478E1FB6AA5D6D146895F73E29C3D5D4981E25BED114515E3891E775079646E9A7970648A261D66EA95C2133FD8E55802359B81C50A87A3FF3F14D427851BD90285EC2C6967DBD7456B8D67CF0CDB0B1875BD42F6847104A8A808621A68B295BFFCAF110EB1EB77A95EE11C29B4C5CC42201C81D3B91A7D4643293A56D91AB06F83C6126D9545EDF4BC4502069F974").unwrap();
        let add_info: Vec<String> = vec!["test-0".to_string(), "test-1".to_string()];
        assert!(verify_schnorr(
            &EncryptionParameters::from((&p, &q, &g)),
            (&e, &z),
            &y,
            &add_info
        )
        .unwrap())
    }
}
