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
    integer::MPInteger,
    number_theory::{ NumberTheoryError, NumberTheoryMethodTrait },
    EncryptionParameters,
    HashError,
    HashableMessage,
    Operations,
    RecursiveHashTrait,
    VerifyDomainTrait,
};
use std::iter::zip;
use thiserror::Error;

// Enum representing the errors in zero knowledge proofs
#[derive(Error, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum ExponentiationProofError {
    #[error(transparent)] CheckNumberTheory(#[from] NumberTheoryError),
    #[error("Error checking the elgamal parameters")] CheckElgamal(Vec<anyhow::Error>),
    #[error("The list {0} must have the same length as the list {1}")] CheckListSameSize(
        String,
        String,
    ),
    #[error(transparent)] HashError(#[from] HashError),
}

/// Compute phi exponation according to specifications of Swiss Post (Algorithm 10.7)
fn compute_phi_exponentiation(
    ep: &EncryptionParameters,
    x: &MPInteger,
    gs: &[MPInteger]
) -> Vec<MPInteger> {
    gs.iter()
        .map(|g| g.mod_exponentiate(x, ep.p()))
        .collect()
}

/// Verify Exponation proof according to specifications of Swiss Post (Algorithm 10.9)
///
/// # Error
/// Return [ExponentiationError] if preconditions are not satisfied
pub fn verify_exponentiation(
    ep: &EncryptionParameters,
    gs: &Vec<MPInteger>,
    ys: &Vec<MPInteger>,
    (e, z): (&MPInteger, &MPInteger),
    i_aux: &Vec<String>
) -> Result<bool, ExponentiationProofError> {
    // Check of input parameters
    if cfg!(feature = "checks") {
        let domain_errs = ep.verifiy_domain();
        if !domain_errs.is_empty() {
            return Err(ExponentiationProofError::CheckElgamal(domain_errs));
        }
        if gs.len() != ys.len() {
            return Err(
                ExponentiationProofError::CheckListSameSize("gs".to_string(), "ys".to_string())
            );
        }
        for g in gs.iter() {
            if let Some(e) = g.check_quadratic_residue(ep.p()) {
                return Err(ExponentiationProofError::CheckNumberTheory(e));
            }
        }
        for y in ys.iter() {
            if let Some(e) = y.check_quadratic_residue(ep.p()) {
                return Err(ExponentiationProofError::CheckNumberTheory(e));
            }
        }
    }

    let xs = compute_phi_exponentiation(ep, z, gs);
    let f_list = vec![
        HashableMessage::from(ep.p()),
        HashableMessage::from(ep.q()),
        HashableMessage::from(gs)
    ];
    let f = HashableMessage::from(&f_list);
    let c_prime_s: Vec<MPInteger> = zip(&xs, ys)
        .map(|(x, y)| x.mod_multiply(&y.mod_exponentiate(e, ep.p()).mod_inverse(ep.p()), ep.p()))
        .collect();
    let mut h_aux_l: Vec<HashableMessage> = vec![];
    h_aux_l.push(HashableMessage::from("ExponentiationProof"));
    if !i_aux.is_empty() {
        h_aux_l.push(HashableMessage::from(i_aux));
    }
    let h_aux = HashableMessage::from(&h_aux_l);
    let l_final: Vec<HashableMessage> = vec![
        f,
        HashableMessage::from(ys),
        HashableMessage::from(&c_prime_s),
        h_aux
    ];
    let e_prime = HashableMessage::from(&l_final)
        .recursive_hash()
        .map_err(ExponentiationProofError::HashError)?
        .into_mp_integer();
    Ok(&e_prime == e)
}

#[cfg(test)]
mod test {
    use crate::Hexa;

    use super::*;

    #[test]
    fn test_verify_exp_3072() {
        let p = MPInteger::from_hexa_string(
            "0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF324E7738926CFBE5F4BF8D8D8C31D763DA06C80ABB1185EB4F7C7B5757F5958490CFD47D7C19BB42158D9554F7B46BCED55C4D79FD5F24D6613C31C3839A2DDF8A9A276BCFBFA1C877C56284DAB79CD4C2B3293D20E9E5EAF02AC60ACC93ED874422A52ECB238FEEE5AB6ADD835FD1A0753D0A8F78E537D2B95BB79D8DCAEC642C1E9F23B829B5C2780BF38737DF8BB300D01334A0D0BD8645CBFA73A6160FFE393C48CBBBCA060F0FF8EC6D31BEB5CCEED7F2F0BB088017163BC60DF45A0ECB1BCD289B06CBBFEA21AD08E1847F3F7378D56CED94640D6EF0D3D37BE67008E186D1BF275B9B241DEB64749A47DFDFB96632C3EB061B6472BBF84C26144E49C2D04C324EF10DE513D3F5114B8B5D374D93CB8879C7D52FFD72BA0AAE7277DA7BA1B4AF1488D8E836AF14865E6C37AB6876FE690B571121382AF341AFE94F77BCF06C83B8FF5675F0979074AD9A787BC5B9BD4B0C5937D3EDE4C3A79396419CD7"
        ).unwrap();
        let q = MPInteger::from_hexa_string(
            "0x5BF0A8B1457695355FB8AC404E7A79E3B1738B079C5A6D2B53C26C8228C867F799273B9C49367DF2FA5FC6C6C618EBB1ED0364055D88C2F5A7BE3DABABFACAC24867EA3EBE0CDDA10AC6CAAA7BDA35E76AAE26BCFEAF926B309E18E1C1CD16EFC54D13B5E7DFD0E43BE2B1426D5BCE6A6159949E9074F2F5781563056649F6C3A21152976591C7F772D5B56EC1AFE8D03A9E8547BC729BE95CADDBCEC6E57632160F4F91DC14DAE13C05F9C39BEFC5D98068099A50685EC322E5FD39D30B07FF1C9E2465DDE5030787FC763698DF5AE6776BF9785D84400B8B1DE306FA2D07658DE6944D8365DFF510D68470C23F9FB9BC6AB676CA3206B77869E9BDF3380470C368DF93ADCD920EF5B23A4D23EFEFDCB31961F5830DB2395DFC26130A2724E1682619277886F289E9FA88A5C5AE9BA6C9E5C43CE3EA97FEB95D0557393BED3DD0DA578A446C741B578A432F361BD5B43B7F3485AB88909C1579A0D7F4A7BBDE783641DC7FAB3AF84BC83A56CD3C3DE2DCDEA5862C9BE9F6F261D3C9CB20CE6B"
        ).unwrap();
        let g = MPInteger::from_hexa_string("0x4").unwrap();
        let bases = [
            "0xA346BC3A7D319925E84488E25F0003AD86C3C331A33E818F68DE307EFEBA49A32134BCD7CA50CCCF46C5517AD2927F5423F5A57FF152F4601AA527BD8CC82878A76A8637BADCDF211175D6AD7A029399AEC09A525EC37E9E7702FC361D39A83D0DA1657E4B8168D39D6757EFA46F8BE119C15C5F003D5720919E3A1DEDA298A963A6247228F616E711FCEE80596C410C7AC532A4699383DC2D158D14C8B83F716CACF067EFACF4B6EA020FF0AEE31B9C000DE3EDAFB7AF844BF4EB7B4452CD26DD4BE7E1C37F820B00142412AD3C57843000B055DD4E78F84C2D32ABE3024F7A761675F4F971FF56378104B67F1479D13562FB20A601CACBED7E94E6A2CE483B2D425D1612B18F7F57327DDCE2F55A23683E66FEF84450B20D8D518285C4FB558A11483D73335357746C3297A0C2C6725508EC4F313637EABF2E6C817A7647C31C731861DAC2AF2083B0A2A584286233AF739C6896F6983403FBDEA8F731B221DBCFEB971FCE25D49735788AD0535DE4584DE74A75696C50CEB5F8CEC0D190FA",
        ];
        let gs: Vec<MPInteger> = bases
            .iter()
            .map(|e| MPInteger::from_hexa_string(e).unwrap())
            .collect();
        let statement = [
            "0x2F388A9C6987D0E4DCC04CEBD8312F637918883CB8777C8DFE5733C2383377CA2278BF22463F68D8F9CE1EB5CF09AC5DFA49B2D267BD7E1F1EC8A4DC6ADBC5FFBB9070FB90BD33E0D51F747C715F26C056CB8CE8A63522DA7D99D2F14217DEEA583D371B677EDCE5F7FF3C0A1F5B80FAD3CA8580D373D47D316D2713C3809E8DD82DD08DC4D808B59B65DF78E137275992A571D1CE23B83B4DB16A3E22CF46C4F20FC63FD2CDAC8990F43C33A07F9C831CA8E9F1A103E5F2F5CB88EA8C3D4B95DD5C57FA8B8CAFDCCC02F5BAE08076B0ED61A033469844CB6055A0F319E643F129B16767F4F8643863E071847F89F42E2F7E9D266DBA1072F614DA82D3F7C3ECFFED63679AEC0682AB563DC648E7513B4D40E3BA5659E6F41DA52EF1A167C927494504A4E27EF792369F9F10DB834AC63470AC610364B077CE93F939B5E8979DFC97001980E5AE28C2A1EFBE9AC063F60C8F90CD54CD17E3B99D817B5135A0912D8850EB5DE3FB6D019833042C815A53141C1FFDCC909B2245C2336497F4C1F6",
        ];
        let ys: Vec<MPInteger> = statement
            .iter()
            .map(|e| MPInteger::from_hexa_string(e).unwrap())
            .collect();
        let e = MPInteger::from_hexa_string(
            "0x5636744690A3B23308800A82E1C482C873B13A760153EF28F7DB42B3ACE49303"
        ).unwrap();
        let z = MPInteger::from_hexa_string(
            "0x195D3C062B40B2DB1F0B6750417B79A4D2B1E851C2C9F521294AB5C2C5343F2C7D1D100634C0C8E2A091B5E0C4604E668617917F00C2A3793A5F0EF5EA007FC5AFDB44F3705CB2C3A671F49C635C6944B6D2C62FE8FD7E950F1872515633102AC14901329A58926353EE45359BB9AE6C71E88D80AB2027817A3BE3FD44D1611E7AA44E5FC8EAA42C12BF14AE3B0CC1ECD15EBA1B1A7F23E5E481668E12A4D8FAD850EDD95EAE72F2814B3F57FF2E43DEEB1CD82D6559BE2E4BA89E2F1881B4A4C70CE5BBDB9D2DE9738E03E4CF9B43BB5CEDAA61BC43E9534B8CE3CB8B22CCCE033887EF269003262A756727B1BCBB38180BECDB322C757CE37E6F3BDB6677EA23947399571C23F7E12CB2A33045DD7374195A88BA1860F27D81227E5239D070CBAB3C4636EE055AF16987023FC8B559EA7363FCEA8400933A8B69C7D96F6AE13803E424E0168AEC25E3E828D6840A45087B9F4D2C154ADF15B18B0DE216C8D082C6969B2360B52A3AC54BDD201D59D4C68E915C26EDF87956AE4A90CD3D48E"
        ).unwrap();
        let add_info: Vec<String> = vec!["test-0".to_string()];
        assert!(
            verify_exponentiation(
                &EncryptionParameters::from((&p, &q, &g)),
                &gs,
                &ys,
                (&e, &z),
                &add_info
            ).unwrap()
        )
    }

    #[test]
    fn test_verify_exp_3072_2() {
        let p = MPInteger::from_hexa_string(
            "0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF324E7738926CFBE5F4BF8D8D8C31D763DA06C80ABB1185EB4F7C7B5757F5958490CFD47D7C19BB42158D9554F7B46BCED55C4D79FD5F24D6613C31C3839A2DDF8A9A276BCFBFA1C877C56284DAB79CD4C2B3293D20E9E5EAF02AC60ACC93ED874422A52ECB238FEEE5AB6ADD835FD1A0753D0A8F78E537D2B95BB79D8DCAEC642C1E9F23B829B5C2780BF38737DF8BB300D01334A0D0BD8645CBFA73A6160FFE393C48CBBBCA060F0FF8EC6D31BEB5CCEED7F2F0BB088017163BC60DF45A0ECB1BCD289B06CBBFEA21AD08E1847F3F7378D56CED94640D6EF0D3D37BE67008E186D1BF275B9B241DEB64749A47DFDFB96632C3EB061B6472BBF84C26144E49C2D04C324EF10DE513D3F5114B8B5D374D93CB8879C7D52FFD72BA0AAE7277DA7BA1B4AF1488D8E836AF14865E6C37AB6876FE690B571121382AF341AFE94F77BCF06C83B8FF5675F0979074AD9A787BC5B9BD4B0C5937D3EDE4C3A79396419CD7"
        ).unwrap();
        let q = MPInteger::from_hexa_string(
            "0x5BF0A8B1457695355FB8AC404E7A79E3B1738B079C5A6D2B53C26C8228C867F799273B9C49367DF2FA5FC6C6C618EBB1ED0364055D88C2F5A7BE3DABABFACAC24867EA3EBE0CDDA10AC6CAAA7BDA35E76AAE26BCFEAF926B309E18E1C1CD16EFC54D13B5E7DFD0E43BE2B1426D5BCE6A6159949E9074F2F5781563056649F6C3A21152976591C7F772D5B56EC1AFE8D03A9E8547BC729BE95CADDBCEC6E57632160F4F91DC14DAE13C05F9C39BEFC5D98068099A50685EC322E5FD39D30B07FF1C9E2465DDE5030787FC763698DF5AE6776BF9785D84400B8B1DE306FA2D07658DE6944D8365DFF510D68470C23F9FB9BC6AB676CA3206B77869E9BDF3380470C368DF93ADCD920EF5B23A4D23EFEFDCB31961F5830DB2395DFC26130A2724E1682619277886F289E9FA88A5C5AE9BA6C9E5C43CE3EA97FEB95D0557393BED3DD0DA578A446C741B578A432F361BD5B43B7F3485AB88909C1579A0D7F4A7BBDE783641DC7FAB3AF84BC83A56CD3C3DE2DCDEA5862C9BE9F6F261D3C9CB20CE6B"
        ).unwrap();
        let g = MPInteger::from_hexa_string("0x4").unwrap();
        let bases = [
            "0x19D43DDD760D53E144289FE63826030B25DEA1BBA1CA04A75976CD0E81460D2A31FE17A50763E72FB756DFBCEA4E850FFE3E1AB12E75A1774A723FA745AB2025BB21662F3D967796068A23F3BB550AE2AEFE2B674F58D61427EFB3F75842AB5F46DD7ADC02570800CC958282FCFF597AEF9B9F4E64EC6A937C45A19BD1124BADD3862A1394617E341256F2D056777F07A82D14B42E22B3586A5E05BC16F79CFD751829464B6997C213F030A28CF45809281323915B67D8C695ACC7CC37DE77249BE624C16BA183FCBD8E476F4BAEB1E2467EA45D6D43D94C48E9D69EE27988B781683604D17CFFFEEEEC25D1E52608D55FE82D602468BCBB72CB1952BC9D56C3299E27CA585835204A9C5B5FD1F9A5236490BCFC9B6B536A5568CF0A5D273D4AFC0151C64A4BA464001286FE3AD0EAB70D8C87FBD6BCC47BC6E449ACC2EABDFD339DED9553B808E58BCCB3F024FA75968BFCB5EA020B9AC7055FDCAFAB3B314090C1DD2D88F86383F5768840B71FDCFA6C7FF29EE7256BB86DB4AE7D57D57827",
            "0x424BFD6EA3ADC99AF84B2F6406C90D6C3AC841752B016702E2347990B85E2013634BCA89092763F94A3C54EB1B2E3787CA537D9ADD0602475B1B5BFBF68819BB65908A9C33D821CBCE3FE9919A1DC032DBB38D3533CCE62DF28BC8774A6044EE7F88C685A71C2098D6EFF6AC204436346289761AB91553A809D7DC5DFA7E0B4A24A99F43E66CCE3D9C631F1ED9ED4DA14464B3921DEC061352DAA7093CA34F04CE5EFF06F47385D401AD413CA463382656F73A58AD4F6D55A0EAA8234CA67F258F31C0EEBB63617A3B59EFB1606082006417B50F00232CF74496E3A43D6EF150D7A4947761917BD5AA2DD02AEADE8E5C761B09307EE673111AE44932E5CE1DCB821364577F69CAC4C8FB2B3158449AADAD06933B5D56973FEA112781BD617EA66B308ECF2197C4693E6CF56D5F06ABCDED20F9A70D7E8FB071B57C7009142C17AC0FB24C4EDD4780095FE3E9A7C463105EE15D88D0AF3DB266FCCB2FFE8521A4F0E13A0901CA70824D579C6817F022E1EF520F718AFB999750F46DFCD23EB9E2",
        ];
        let gs: Vec<MPInteger> = bases
            .iter()
            .map(|e| MPInteger::from_hexa_string(e).unwrap())
            .collect();
        let statement = [
            "0x5906F09D47C48B3FEEA97F003175033DC718C6079A6F7E439F3998B6AFDB79873A7C9DB306D401B4A1AA0E128331658C2A50DC2962B337FF50D523CFD9B20C4EEBC7A761C84F6E187A59AC0FE466B831714DA06C5E02EF3132B10BDEC4591BA9D3715AC47EFE5D15686487F48E7D252C20453EA339DAC4C671C128BE687883305A8C6BEF8F8F14B20358C9D46F82A196ABB4FF984B046FFABA4ADA2B18401AE64D6E19A3C99905F3A0999623AADD5DB3B772BFA82640EE0401A47308E61A2C37A8D3435D60143693F01FDFA16977B8F84A061C21E87F091D072A8797AD72DB408281DF3A482DAE9A8441B088F3D6B45937FB861EFD08E9772B33E8AA308FDD07B019F7DF60959640B8BE4FA27BCF0AC52D8E1B522DD78118EF2531EE43F29B5A8889D95100C0C5E8058319F8DEF06E5F7491869CA09842B74F374292780971637D6BF5EA966B4C1C10F15980C58AF82240F76FEDCCA0F285E5E672A6BB0993600C472C4B9FBB2AA6F51EDAF05431693ADDB34B87A1AAC16D47F87FF7C42B3566",
            "0x329E07B476E4F0F97BD3DAE33757A621DD589C990AAA9CB14FA7E498A3280C2C59E3A518FBE75753AF142490897B796E0C594CF1C767A5511C46877946CE8135BDFB5FAFDD0FE998F91F46B966870AE332D47C5B37158EE3525A9C68D3DB01BE2894BD9D1171F77F70B8FA3193A68B78E2FF507F45F228DE696AB6F86C6232E781BF6E905E4A7CAF1E31398499C55622F89468597307702854CA5876A3D93BE29F4F996FDEFED23FFDC904CDB781A1F5E833AF1FBB2349E83D05BC401DADA2CCC58A3768A9B1B413DEA7D0F69BB991F658C7C3E0BDA5F570D5FA907E0EF6099406B02BD4EC1E75C4DDACA675C396F6E6E7026F38CBA0CCF7B74CBA6D3263B4BC7B1D4D348C6C7A84A7B7B31FEECF2C307132E65B37C345E7CA1D8C213E6D0AA99393BE1AF87220CD30F39A465DAF1CDF4274991BD4DC27FD09BB214B16D68B1FAD233D2ED25B559F6CB98C407CD0104F0CA2B198CE353B3869042F1C9750DCF0671A2CCB5ADFF120244B0828F86873F14C975ECCC17E8A797A6122AAE89AECE4",
        ];
        let ys: Vec<MPInteger> = statement
            .iter()
            .map(|e| MPInteger::from_hexa_string(e).unwrap())
            .collect();
        let e = MPInteger::from_hexa_string(
            "0xB1EA73A8BE45C17E6416A8FB86D326C580A86FE31958D4A7F7FC76E9981CB690"
        ).unwrap();
        let z = MPInteger::from_hexa_string(
            "0x4BCD5712846DEDA293A5D164F945AE1FA3CA3F1D6F8521235532AE5663238BE5446CC129CC47EF25E5A34C82CAE1837D462492D488CF9966E0928A013E7E81B995A1375A0219EB8451E269DB6486CE99B180E2C91FE8F52F236993A85573808A3F51DA9519510B4AC489F8B250A886F32B87519665E7A229FCC525CA72FA8B565D546456A77F52EC9F98488A98553C56B2816C28FE4609C1DFA77FDD53E08385DA32770B659953340B6AF62900934F3BE11F7A2D313BC977DDE8BE4CEF3461135B81825296FD8E9C588A0BDB2A0BC60D88EC17E93B7A6AADCF3000F8D2877D0CF670F9042B05CE739E8D804E85C6996E9DF42AA0D866C02C5F33152133E7023CBD259CFCF85770BEDF674D7CCA334AF7D0256873CF38EF9F1C9A500A01BFEBCF1E5317D72255D1B4F24CBBF5CDFAB1F51801CA96053A08F52539DA4B2B29EC9D830295C78360E0947BF216EFA395B714644A3A7035A2D2FA2D7EFD7C5DBD54CD7A352955CE810B175D17180FE11EBC207C7B91AB46B0C40765E25AE722F0B9F2"
        ).unwrap();
        let add_info: Vec<String> = vec!["test-0".to_string(), "test-1".to_string()];
        assert!(
            verify_exponentiation(
                &EncryptionParameters::from((&p, &q, &g)),
                &gs,
                &ys,
                (&e, &z),
                &add_info
            ).unwrap()
        )
    }

    #[test]
    fn test_verify_exp_3072_7() {
        let p = MPInteger::from_hexa_string(
            "0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF324E7738926CFBE5F4BF8D8D8C31D763DA06C80ABB1185EB4F7C7B5757F5958490CFD47D7C19BB42158D9554F7B46BCED55C4D79FD5F24D6613C31C3839A2DDF8A9A276BCFBFA1C877C56284DAB79CD4C2B3293D20E9E5EAF02AC60ACC93ED874422A52ECB238FEEE5AB6ADD835FD1A0753D0A8F78E537D2B95BB79D8DCAEC642C1E9F23B829B5C2780BF38737DF8BB300D01334A0D0BD8645CBFA73A6160FFE393C48CBBBCA060F0FF8EC6D31BEB5CCEED7F2F0BB088017163BC60DF45A0ECB1BCD289B06CBBFEA21AD08E1847F3F7378D56CED94640D6EF0D3D37BE67008E186D1BF275B9B241DEB64749A47DFDFB96632C3EB061B6472BBF84C26144E49C2D04C324EF10DE513D3F5114B8B5D374D93CB8879C7D52FFD72BA0AAE7277DA7BA1B4AF1488D8E836AF14865E6C37AB6876FE690B571121382AF341AFE94F77BCF06C83B8FF5675F0979074AD9A787BC5B9BD4B0C5937D3EDE4C3A79396419CD7"
        ).unwrap();
        let q = MPInteger::from_hexa_string(
            "0x5BF0A8B1457695355FB8AC404E7A79E3B1738B079C5A6D2B53C26C8228C867F799273B9C49367DF2FA5FC6C6C618EBB1ED0364055D88C2F5A7BE3DABABFACAC24867EA3EBE0CDDA10AC6CAAA7BDA35E76AAE26BCFEAF926B309E18E1C1CD16EFC54D13B5E7DFD0E43BE2B1426D5BCE6A6159949E9074F2F5781563056649F6C3A21152976591C7F772D5B56EC1AFE8D03A9E8547BC729BE95CADDBCEC6E57632160F4F91DC14DAE13C05F9C39BEFC5D98068099A50685EC322E5FD39D30B07FF1C9E2465DDE5030787FC763698DF5AE6776BF9785D84400B8B1DE306FA2D07658DE6944D8365DFF510D68470C23F9FB9BC6AB676CA3206B77869E9BDF3380470C368DF93ADCD920EF5B23A4D23EFEFDCB31961F5830DB2395DFC26130A2724E1682619277886F289E9FA88A5C5AE9BA6C9E5C43CE3EA97FEB95D0557393BED3DD0DA578A446C741B578A432F361BD5B43B7F3485AB88909C1579A0D7F4A7BBDE783641DC7FAB3AF84BC83A56CD3C3DE2DCDEA5862C9BE9F6F261D3C9CB20CE6B"
        ).unwrap();
        let g = MPInteger::from_hexa_string("0x4").unwrap();
        let bases = [
            "0x7EB4024B94CAB4AD4CDC372C5D36F061D95D06C5325A97806B448599185DF594A193B7F71AF67E34239AE17673408DFD6705981A5F55513BEBA214098836B9FA9E8D8924BF1DC85977860BB2E75247DC80D49FD1D9B54A96B5AB23EE77F4ADD64093953074CFE7A8EE1B79204C2F1157A091610F2C4C61651D5D78E78AB53DAB99CB385A5FEF7B0EEBE56C95CC460A9BD203D89342D161868A7B17FCBB417A9663D39D7D09C8F54867231AC3D6E4AF3FB8205D0AE7784046D5F86DEE475A8AFA8BD1C452807A37FFD4ED0B892875AC6D318B546661E8FB7FBDAF5D0D84E9026EC87803DC0487D1FA5C647E2838FE7CC32D03ED9E1F90B46D6BD2915C2E07A50B4A09E60E93F87E74D92FAE05037B515DF797F3E8E3327DC921773ACE75B66289516DBF6DAE624599DFD0AB4298CF881418726D97338E754A8479F1B87F5C48E7797E84B0C10DA40B052E2B96B01418DBEC0C9949A11BBAAFC89658770F8B7656D157420097A1265303E6CE79C181CA39981E349E9DE7A2714285A38B64E2DD33",
            "0x51996FCA06E00A3671C965F20BA15F965C7F41F5D2A016CAD60F782FCA80772D09A0FE6F1E56FB014830F218AFC0DA9DFEA17B91DFCBC569E7556BBD5C72E42F67B72AFFB50DCAAF2E83A64A37DED91135366055EB0245D38BCCC87851A3513968CB93CD6C3D8DE0BED1752A73051E7B69C17BB6707C45CBD5F33F722D25653FA512C2EC32566F9D5D63237A754979E315ABCC7D3DC992AAB9B472518F8E2134A581754BA60DDF8F4773CDE6DE913DC1E7F2EA750EBE5ED836369FE5C4DE495E7009BCF17EDD9292D623990C0236AF60437E0ACDB49A2FD24657B2EA1E0B9530E262CD7563DEE6AE96604A3D9AB127B04B52C7C9771C653800A4C841F7673256E1FE67944FFDBA49411D3FFDCA0C1BEC30B9E173BC1BA42ADB6B7DBBA9606E5B51B5317E01DF0876BE41C4A653FF2F6CBFBBE5A11BE83129B1F0D4835D2F63BED3C890234BF2161A9D9EE14239E16040048CD0F7A3CF47B3047756FA8E5236FF7082CB0EA1ED8B04A27B970487C3846069EC4B0485662D9389A3F4231E05316B",
            "0x10068C5812CF679CE4C0FE28E39F18EF13CD44D8A3E4D218760E6BE35AAA1F7E3F00A1E16F6428699A6B6C0EF9A889E1E5D493FDB054AB75351E9910C38C87AF37DF9A0FBCEF4916B562765A1EA7C2DDCBADBFC81CDFE6A922B987E3FA8C3C8D878C4768475586AE710DE6224732565BAC1043C96DDAF76784A9B95DF0A544744CA10F0DC68A596DD1E89412715B60A34E00FADA7F7B98EC68F2F364C7FAE9C0BE3DAB32F0C4200C7DEA64E599E0BC89BE71F22E1600974BF69865A6D9C59620108AC275A9FBD41AB6ADA59CF8C8D7ACE02241E34F269F2C27A84D83AEE49F3FB6EEFEC91C4585E42249776DC4A92C1E212A720BD3B20AD943A57B3C08A197CFD13C0872FF83BC134C78286D0153D46AFFDFBDA029903CB967E9BE2A75A31582CAF9B8BB23DF0CE0622DC948FA02839026C3EBAB800EB16FAFF9E6AAC8787066588C25DE35B877FFF8701F89B69B1CEFF97E46C1147DB87A5778B6561A93B600ADCE21734B4F9E6EA64B07F25ECB17BA84A56BE7875A183D04DA420425B36C55",
            "0xD677DB25C19C51649ACFA30BAE2947C23D2A1B73D4ADBB7742C3E045B499ABC89B36AC0CE27D7A0E5A5532C0CD24BE18B913B953A3E71E6716B0FB759E3C3401548D67253521E9AEED70EFA64B0B3D0B7CB944B8729E9D4FB7FB38EBA0FEC53B56D88D8A7562F3E997084C9A4E3AEF8354C07AE22F3E7349EC8A3FC30295996BD06A7AB2B250F37B849F6ED5A3EB51028081B5D23F044565DF25BA8E4608AAFD23CC5CDC84A8A4E203C4E26E0933E5B8D66B66DD433C08E9B8C45507B2C2977B0D2138F49B09F586B61AC82F5A30F124967F298DF06A47F52690A2C667F9E3BD718C9600C9E9A8836630C3DF5C7EEC8D23DF4BC92994521180B8159F3490186740EE162127472AFE09D0406A4CA2320D90FDD545B97D4634A3F07A4E193CEEA59AE99612188DA23EC54E21E245B76FA2D5241F13C885EA6837621F6C6A6F7915723A8946A3ADBFA1D6AF03632B3B79FC146CDAE56EC0A674B6216BADB29C13BF1A9D09103F5EF55BA6C463190ED5FCC0D3C37E1BCE31A1381DE9C319F9C300D",
            "0x65FC627DBA256E8FBAA214E5BFC765951F0BF70D87790CB9CCCF43B16B1DD1EF3CD9AE32F929D2DE224A708CFB987C6316E0904D39E802B0C2890DBF0EDDC7C5E1B3DEA219DFF9B6D2CCDE61738F8F8D8DEF60A6CE605AD445E69985EF52D4DDAF458CEB034A63BDB3356F96D9BE30D3C654EEC4C97B7C4EE8226C2494466A65B382A62E659E3544D2836661F00E14CB6979EEB857918993A10A81CE9180DEFE499D161B4B0A71B3D9E26290F3CED598BB5511AD8D681E1E064F344AABB300284CC6C4096EA3B8E00241FDA017451FE6542BAA07A56CD33E66DA983C627B7660D6CC270276BF4A3B205DDE5EFCCA32FCAF163678BAE87F9B32146C1DD255CD9F4A04DDD7CA7C728652EFBFCE6E921A05EB09A8E171BF1B03FFA13713DD642FACDDEA3DF2E032FB344A52600F7EC5A3FAA97A542F4CC6DE97C5F7371C7A02E6D0996376E292183785E6EE544A4AA8E1DE41694A3A25259D2122251A6D534A5608C919AB238061CE5EE778E0A9418101EED7A7C775BB02FEB0B315F76C92F670D3",
            "0xA002CC6721E036B6117DF3E5FBF14502AFEDDA1B1B61C221DF7BDFA44E3C3B9BDD82D6E2732430769237919B7BB35251BB10EEC7440DBE2DD2D2A05292C56B456D57C83F0B1E24E5C5CCA6CB2DED1EF1978BF0894ECC33FDE413FF7454634CF9C5CCEFCAA58B26E44FCBF45F039582C7752118CE5F8093575BD4E4BC5563C5FF7330BA959B6022CEA7A479FF66D41D6B4BF94C948D443FE53294A64F6530B7FE7AC919A92BDCF4786DAE7D43B3F93F9D1CA196F6D2DE2B25ECC943F0FA6BCC1723C08912628D95EEF0E8EDA19DFBBFFFE4F84676A10EB32751033BCB025C201A26C1BE4D6478A5913569C140DBC7BD596317E024FAA827939DB7E8740138661F60F0F90FFF061F6A12053769C89B805B05712F01D6137545F048EC6BD649EE0AF3098BCEAB6C958492F541F591F4BB7308D3E6D85861E1E6410C0BF175A552583471D82294D978C151C601E626C3F8303DE710322F4646DABB348247C5442C5763E04B402229702E643D01A39A769619FC5FC50EF091D4D508A1562B6D8543C8",
            "0x6D522AA61E36EC2EE8721B046E20EB146FF67094B4B998DC9887D958B09D7F8F256DE8E2D7C4094B0C2F8B1273A81CE2BE525FE0685CBD8D2232E696EE280F3C60D38B0FB6F87E68453469047725FAA0A521309B6A31CE5820C4DAE37399574605A224A6CAE44EC52B4E19C119E37ED619EB67C4F6ADD7CCBAF4A1437BCB2105E80630433FFBAA56BAC6F2DECC239081E8861851AE1A8FE6C61F638B0F27A42918036E259395665B679F198A9EA7237128CEF6A7D926F1BDE2EBEDDA19F83E979F534BE690EF4C761F008D7AB76D0BA96DA3526CDDEEA75D74A1AFBF27487723933E177D4CCAD22E62621CCA718727765658518F265F3336514286333DEBD64EA9F2480349489BE744471CE424356919D5AEBF7F77227E97254217E02731EDF46BD496C5A405049D537F84D58AFE6D77BF6EDFD157D2696C517CD97B78BCB9E42108830AF3882DA99F716C789EDFE9F41A18C05463ADB0062E4CE619323999AFC163808B759DD20B0CEEFFCC104D59E6FD6F492C87BDB6D1CA9753D22E55F64A",
        ];
        let gs: Vec<MPInteger> = bases
            .iter()
            .map(|e| MPInteger::from_hexa_string(e).unwrap())
            .collect();
        let statement = [
            "0xD4EC1540CA5A63316A708C9BF250DB429D8D4FB69828AEDD09684913878B24422295C5F79BAC03B3C3D3B16E66AF066B229706D7A286C9D8F6B68E93CA8C3D91FF0E7367AAB7DFCE192E763B8464E6400B1F64A04C75B2F519C8E5D8ADE02FFC24B754CE5EA3FCB96E63A8BF90F86BA4666AED0327FD61347926E2D8C7C843E09039514E5399A89384E175D443AB831573E3FA9BDE9AB0D070860B35A4BFA50AB692B60660B190E9060A3F81F81DABF20112863FB0254D3E77B6CFDB606BD74B648A37B4001D562EC62BA8AB960947FBD8DB77C17AA0E62C4A4C79673C4AED8C0EFB240A863A5598E8C53749B147917C3B11AE724BC29FEB2FE4B2A9F621E871277B47EC230970522F2AD53E5C0BDF10601653C80D77C91547D093F735055551DB9F36BC54D215097B4DAE6EE6157BF60E5E73ACD795364F4F825F291D5AD79491CEE478ECA5543B93FAB37DBBF851446916554EB0A356EB5E68744AEAF9E228AD598B1D80DCF616028D3165B0980EAD3647443C1822843DBADE9E1EF5E278",
            "0x69AB3A45192BCCC5FDD628D75CB5C27AC838C0C716D2C5B1C5EF62DDA9AF22056E02EE177129FAA3EB8DA013364A6AB639BA754AC107FAEDC04DAF65A17BA3532C7DF4F5442C28D5C270DD7DD4828B4F061051CED6CC7F43020D79746E5C8BDFEFF5077466A41CD0008463B2F3FE3B0D009D3E659B3130866C20E0A4C229CCA861920A69D439835D9BE358843F11A1B514206D4A46BD9AF206007BF4CB16E3C8D69E734DC3E694B2507DB70BCC8086B1A5023F3F889B4F75C86DD85C9BC3BB9950DE6A17BE42FFC6A85C614160474D5EE07E88F98799E5151A0822B19E01F9D0FC9C8E8E165FB65B8CBFB4EF590939B7BE28797A7F892CB2F731FECF03B4DD4113683E630FD7CD27CEF2065744527D6053CEB775C0CBE7CA73E5D323767F885179ED8870D83DDFD7D0BE8213B3645391D4D0C24B3B9B17C82D7198CC259E25F5D5BCCB066D5AEF580D5325CC7E197346AEFE1CF4F786CA83B7E8BA0917AECA731A7B9B0CBEB6F6D9131D010CFAE4FACEC773EA2326F94C8DB06DEBA6AA55B5BF",
            "0x15E55C1004EC0EF33C032E2C1652C9AFEA4CB5EFB10F729033D2EEC197E07EE5B36C160CDA9251FB84A1E4F49B8A0ECA5679C1249563675613034541786DF15A5D006C1BAC3B6A9F75D21F9B9D09029E583207BDE4E34F70AF3E7F161F954EBA319C3EAFB1DCBF9C2090325F67B4148BA81CD6838339A83264E69B8355D543239569FD55D2E29C0E199031E532359243C1C40976909DE0F83C61CE607BE6B0203369659F7D45278E5384020387E9D85D747CAC40FEB1438038FA2FD1FD8B4DB77B6E7268062E16B884C557C682230442F611503F1BC83C697E2E03F6C839A7520539EC4C439D501CD7B09A6B4B2F09C52FB0901E1C74C82BA8350C7D62267FA0884C8104D549CA8DDB46101BC3E42833F72FE5CEDF29600DD7D7932853048C54DA3E05FE26D32B3CFED3B49FCC9DF226AAEF0E314ABC0A76C9B615BDC789CD524C6D4119E0DE361C1B86045BAD0A7E9F7FBD14C870CC76AA1E9960326ADFBF93250B3195CC874712F87820BB166B70ECB133BD07964940CAA9314DE63D89189",
            "0x71C7C3E78423C749C02E95AEACFA73C1A7E9B1C39DA578F7DE33C900ACA41E94AEBFD465AA61C1E0BDDD6181D6501FB101BD08F414103DF0F21C94093580DF6B02682B71A5F97DE1D3375C4A1929026AFE20B9A1D000A8C0A3FAB3793278B00847AB6B6742107A1408010C099AEC6B306C56CA4B661EF7816FCE8DF818C1D50E5473C53AC9824A63CFFEACF13527E73972F557A2AE4B4FB4B0006FDC3CCD9F6B67EFD8C19A217331D01AA836AE54F00D1C24724CCA6D7D37A7F663B39AB1E83E1A3CFADF4A84F695DA8BBD795E4519F843AF25235D985AAF91CC90443C9EBD0FB59E90CDA6B279825687D82A21115D01C8889992573EDA7A8878AF8609B61E43FC74E0C15F0569B6669A7FAE2376D6549AB25D5ED19EEE90D98661F93EE6290675F642A67C051355B27C7DACABC47FFFA894FBB590B20D3B9FF3A17789ACA1FE77B5254625AE794C41F0D7CCF39F1DD263230C1324A8689362FE051636DA4A3775090FF09C507A7A95BA50C13228A407E01F9E417EB732080B66E934253531CC",
            "0xAADD5A3FDA41E6AD819CD2B159C3270EFBE2EA800E1F528BD8C3AAD3D07200683E25FED9B16A07540C2E4248ECB9C897A6F3DA116ADEB7BDC3F82EE7B6FCE56026C0DA41DCCDA4562491501F991F43045A9F8536C7481C77EF36DE83B024935C53329F1053F6F5C04943727F3A4295F0DC3A4C994AD99BC56563379AE42CD799F781D3EE534F3211ECBB72530AD8A54BA2EDA76ECEBA20C6C2000C48DF8683BF5F3F76700F0997319DDD799BB779105F9DB0B161CE64700761935FC3A25037C11420029B913D4FA43120875F9168C6880526C28CA596AD9AEF90D0535588B1D1B6FD892E68D631E6E5E4933F90DDCDA8E1D0791B9D6CD8F47B27E4A1194A7FAD48F56B620E2602494A05C28649F3AD4416F32444B3396EFD197D0722FA1794621C08C80760C3A41EDD2B6A2F6A4EDD91B4DCEEEA420164A56034E0FEC4F876A078C272EA7595084B8AEFEDF5B91458FC3858DA7E733B94BEF5DF77409781B4B59FFA1274D139E655EEC6AAA2F8B7F57134FA7C9EA0C4DC861D3E617104AEECA8",
            "0x6749859F0A3983C7EFFFEF50BAF58FBFCB8B9100BB5754BB34178328B86B84F7175347F03243A600C90238F1157ED274359CB525210E9B09A053E3160017A935FC160FAAB5249CDE4015C35E6A1C0087C2010309FD956D421865BEF1B7821B852DF761FD11E24CCBDD92FE176FA791CFCB666915A851502A60FA63008CA20B20DDB11F123DA9DADCF5AB2B777F948EF8076DA61E66B8235107D568B03558E144369D16ABAAAE9A24A38068E4A1806DE007115E9D07019D30B904020D15A39942334D8BFE4216ED12839BC748B4C9F18DF289E02FB73CEC2F4D00914F2EFC9C954AA1026F541E8DB261E09535EF401F8607452B161D8CD8CE0581D54F829F21FB78B4E15FC5B90CD4582AA1436C02AD6F577A1F69624A3096DCCB2303795117F6A18216AC42A56EB80F8C9187F88134419C5B5D71F17D759FED6D245B2C0D572DBBCB1F272CF7DC1EAC6A8A15F402E22EB79040152AC570EFDF3DCFBAFC63AB6FE80C79D689C3CC93DDCEB2EA646F1681623F2482D902C571CD1AF425AFA63096",
            "0x23049B3CBF31FF70147DBF241A712C3E0BD793BE2D320DA03B36E4DB32B465D33FDF4EB3141FD185F5C46FF1F332596A33C7E5B3902D3AA4626BB09219F4C68B5799FBDD3FC4EB778E009E24275E46C190C9DDE9B9D6C9B7225E6C30970B95F2A70745113101183A387BF556A18FBE347749712F1C0989168F89AAFD5579A74106AD6D3470AADDB90AAFB9060A32EA940C8F277745FCD58AAD986D882AC1CC3CE0440BBD41DF25BB35DCF74FFF0E1472B0E296AE65311BABE7DB612A6D8FEC1531647281BA7E38010420DE292E8A23E0561A1CC77E7D44106D7BEF8257097A3B9CB57CE6080E445169C1901B9E7657D2AF3FE76C025833271C24727EEDF86ECE1C0D9A9A6FAD196F343AE2F07901C0D20B28290CD78CA67C4CDCFA708B1F4375E871CDD11AEF864481EB9F25FC535A5AFB282121A1555C175A50A9D4FE8A24F88CFBC3778B4B4BF44CF39D1046DA6034C52A31D12B9398E0B3198D1DEC093AB8B5024BEB1BEB5EE4C788295BEA483BCB144CD35853C77F17F501BA19BDFBA11E",
        ];
        let ys: Vec<MPInteger> = statement
            .iter()
            .map(|e| MPInteger::from_hexa_string(e).unwrap())
            .collect();
        let e = MPInteger::from_hexa_string(
            "0xB5706811B59D6CE68F85A5F84C87FEA0A259DADDC0EDDD2CE43ABF73AE26F0BD"
        ).unwrap();
        let z = MPInteger::from_hexa_string(
            "0x1A847DE8B2512725C0C77B01870AF3351DA8B59452B2865CB745F7A7813AE715DD0354CE735F8B4978C39EDF74AE81961EE03B96C9AE2FD9218FD6807DA1A9B5A05B98C68C6AF4B13159B7D9A3F4A1C4296B49F0D55EE7442F9A3D96AC98123E9E334AD2DACD53F0B8A9D8FFD2AF819C714182D2955EE1FAF2AA7042E55514CB7A2B6C5F269E99E6875AD4D3A6F09DC2FE662C15BB3F17D33D86405D7241F56F7106903E31E85FAB830E257C8366FD8C0D01FF4A65545728F27E0EE632EE00D012F00B1EA1320D268389C4CBDC744D51634B5E9CAC31C35731AC6B3CF26D6578011EDDAFC32D86B478C58DA5A256E383343326326C5A18B06E32754CA989AE62A655652EC39971E89CB42A6FA395032B349C58150D704646203A08E71D3E9CD53550DFAAA2CB21DD4AA04B531716556E2FFAE060F4C2B03AD696CF04B765A04D4DAA002EB2C4747BF91ECA87C9F1B71F8467E9C9EAF8909632BF327FD52B6149D9E6C98F6B244D400E64442477A44150BF47240438CE7CDF3F88E4A851E07208"
        ).unwrap();
        let add_info: Vec<String> = vec!["test-0".to_string(), "test-1".to_string()];
        assert!(
            verify_exponentiation(
                &EncryptionParameters::from((&p, &q, &g)),
                &gs,
                &ys,
                (&e, &z),
                &add_info
            ).unwrap()
        )
    }
}
