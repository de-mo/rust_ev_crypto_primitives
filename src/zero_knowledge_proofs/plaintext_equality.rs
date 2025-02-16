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
    elgamal::EncryptionParameters, HashError, HashableMessage, Integer, IntegerError,
    OperationsTrait, RecursiveHashTrait,
};
use thiserror::Error;

// Enum representing the errors in zero knowledge proofs
#[derive(Error, Debug)]
pub enum PlaintextProofError {
    #[error(transparent)]
    HashError(#[from] HashError),
    #[error(transparent)]
    IntegerError(#[from] IntegerError),
}

fn compute_phi_plaintext_equality(
    ep: &EncryptionParameters,
    (x, x_prime): (&Integer, &Integer),
    h: &Integer,
    h_prime: &Integer,
) -> Result<[Integer; 3], PlaintextProofError> {
    Ok([
        ep.g().mod_exponentiate(x, ep.p())?,
        ep.g().mod_exponentiate(x_prime, ep.p())?,
        h.mod_exponentiate(x, ep.p())?
            .mod_divide(&h_prime.mod_exponentiate(x_prime, ep.p())?, ep.p())?,
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
    let xs = compute_phi_plaintext_equality(ep, (z_0, z_1), h, h_prime)?;
    let fs = vec![ep.p(), ep.q(), ep.g(), h, h_prime];
    let ys = [
        c_0.clone(),
        c_prime_0.clone(),
        c_1.mod_divide(c_prime_1, ep.p())
            .map_err(PlaintextProofError::IntegerError)?,
    ];
    let c_prime = xs
        .iter()
        .zip(ys.iter())
        .map(|(x, y)| {
            y.mod_exponentiate(e, ep.p())
                .and_then(|v| v.mod_inverse(ep.p()))
                .map(|v| x.mod_multiply(&v, ep.p()))
                .map_err(PlaintextProofError::IntegerError)
        })
        //x.mod_multiply(&y.mod_exponentiate(e, ep.p()).mod_inverse(ep.p()), ep.p()))
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
    .map_err(PlaintextProofError::HashError)?
    .into_integer();
    Ok(&e_prime == e)
}

#[cfg(test)]
mod test {
    use crate::Hexa;

    use super::*;

    #[test]
    fn test_verify_plaintext_equality_1() {
        let p = Integer::from_hexa_string(
            "0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF324E7738926CFBE5F4BF8D8D8C31D763DA06C80ABB1185EB4F7C7B5757F5958490CFD47D7C19BB42158D9554F7B46BCED55C4D79FD5F24D6613C31C3839A2DDF8A9A276BCFBFA1C877C56284DAB79CD4C2B3293D20E9E5EAF02AC60ACC93ED874422A52ECB238FEEE5AB6ADD835FD1A0753D0A8F78E537D2B95BB79D8DCAEC642C1E9F23B829B5C2780BF38737DF8BB300D01334A0D0BD8645CBFA73A6160FFE393C48CBBBCA060F0FF8EC6D31BEB5CCEED7F2F0BB088017163BC60DF45A0ECB1BCD289B06CBBFEA21AD08E1847F3F7378D56CED94640D6EF0D3D37BE67008E186D1BF275B9B241DEB64749A47DFDFB96632C3EB061B6472BBF84C26144E49C2D04C324EF10DE513D3F5114B8B5D374D93CB8879C7D52FFD72BA0AAE7277DA7BA1B4AF1488D8E836AF14865E6C37AB6876FE690B571121382AF341AFE94F77BCF06C83B8FF5675F0979074AD9A787BC5B9BD4B0C5937D3EDE4C3A79396419CD7"
        ).unwrap();
        let q = Integer::from_hexa_string(
            "0x5BF0A8B1457695355FB8AC404E7A79E3B1738B079C5A6D2B53C26C8228C867F799273B9C49367DF2FA5FC6C6C618EBB1ED0364055D88C2F5A7BE3DABABFACAC24867EA3EBE0CDDA10AC6CAAA7BDA35E76AAE26BCFEAF926B309E18E1C1CD16EFC54D13B5E7DFD0E43BE2B1426D5BCE6A6159949E9074F2F5781563056649F6C3A21152976591C7F772D5B56EC1AFE8D03A9E8547BC729BE95CADDBCEC6E57632160F4F91DC14DAE13C05F9C39BEFC5D98068099A50685EC322E5FD39D30B07FF1C9E2465DDE5030787FC763698DF5AE6776BF9785D84400B8B1DE306FA2D07658DE6944D8365DFF510D68470C23F9FB9BC6AB676CA3206B77869E9BDF3380470C368DF93ADCD920EF5B23A4D23EFEFDCB31961F5830DB2395DFC26130A2724E1682619277886F289E9FA88A5C5AE9BA6C9E5C43CE3EA97FEB95D0557393BED3DD0DA578A446C741B578A432F361BD5B43B7F3485AB88909C1579A0D7F4A7BBDE783641DC7FAB3AF84BC83A56CD3C3DE2DCDEA5862C9BE9F6F261D3C9CB20CE6B"
        ).unwrap();
        let g = Integer::from_hexa_string("0x4").unwrap();
        let c_0 = Integer::from_hexa_string(
            "0x5A8CB46DC89ED41F690504348A2D85BC1D5BD631090086E4582957DFB9BA9350DC4FD7A6FD4FB64C3A26AAAE5207FDDBEC29DCD24B3717F8ED834F5E0948B59807F1796C20B5BB21F0684CD7E09A6E8F0025BD9746C697D7E073DFA396CEA11055846392DBD22F03CD250D7C169511BF5A9DA265149F2403C24983902D380C85FD0760277C91FBEFD0CAA868817ACE7D09806FB0122B34BC37FF66A8DD386E70EA8A50F418C9B3A2951B1A5BB62F999F707A052AF6A5DEF3AD966722659623AEF6D100BEAF7A4967B3C769EE0F0E77349781A8A9AC52501DC32A9D304DC1A4CB2063525FDF17693EA52C6ABCEFF78DF847D547616899DFF13E1E1A2C2401BA8D6AB28A7F57946246B21634948DD5801563CCFE05D19F61B8EE9CD2F6B245705679866DECF4A65334AA9AE3FE7AAE9E35769910E18108F206840E196CBCA9E81B6D30BECF1A28E6911D68241B4AD72667D2C783602A65CEC6C0C016D6117D874DE05E49D8C851F052AAFEBFD373EC33E7122A99BDC4E34A02AE475E8F81A46E71"
        ).unwrap();
        let c_1 = Integer::from_hexa_string(
            "0x3B5E12E6C5937ED234E740F8C97251C151DB29D64695E127E9326A234CB9A8A0F9772216B745C9A13EF79558467DDE50B38A33F71F47A579EEE5C144215C73465C24F3F8A742B845B92547D62A7AFF27FBC567E98686383CEE71705834837B313634FBEB178A772C0F1A81DEA097C45D5F63BB3462F8323E97607518B40CDEAC8BCD420B71A05642A607D3E579581B164BFCEFCB09C1FFECC487EC3A28408EC8BC01248274AE23E269C1E9BFE7632F17D7F48A268F3E6781DC556FE7A530C9AFFD740D1851322B84C30A7F9DEB99203F520953AFBFAA5E963DFA29607B2978B10AF043AF4789E58CCD3688D570200CE66699DAFA04CAB25D36BFF295903A91701DFC85302AC1D7882DD3516ED4C334FD12FF59F40C4B2140F2E2C7D58538C2EB3F2531B99FB54DD1AC313B5E862C310DA2166E4BA1B74583783D602C3BEB3361891FE8DD10CFA4AF48E5E010870EC040E281759FAECB1B63D67EAE746F4B34D0EB9F1394ABCE569B17397A9AF22D7B677339E59A052F7CFBEF70CF3E7FD06B7D"
        ).unwrap();

        let c_prime_0 = Integer::from_hexa_string(
            "0x3FED60B27121D224CE87B0416997E99C768BE01B5A18B56843FFE36E6EFDC002159BDC90F29718B87FED070588B6DFDF8F95737F288BA6F1ADFA9CB58506A9F06F6A8FAA13A8F87B3F81D030ABAD0F5C1F134B0A4AA517220877F0F70B48B4C84CBEA0F3695FFD50EA58DCC5B24B81698368E5D0C7155158F57659892B17951158F029FE96B804B292D6047E8D92A78EE7040796C5442DCF027A48CE398FB647B233DCAF549B04DEA10EC02E3D0073793F8C46925809B7A25E60635CD55D2ACF3D5D8C8DB009927AB1C6BC566DD27C11EC2F9A331245E0524708B87EC486AA32205699AFF1BE22A8AFEA56B916D3B136D94167845E381E60A57E0517F8A094600AFDCC066BD85D73BA5B02F89F4421B5660843E84F7EB50D9F0F3E58161460BE21C5CD4B99D68FD49022A600504FBA33A79C56AFEA92DE10768F70AF19B7A5857DEA35A7B0A7A9D1BBA092AB53713F03D93DE71D3A48ED76332C18C32ACDA57D3BE7F6B252AA9AF5CAEE3FCBC19E779EC91CC3D749BC64DD46BE2A29273B4113"
        ).unwrap();
        let c_prime_1 = Integer::from_hexa_string(
            "0x975E805E6FB2D4445DEE782E0A61461A2A0B7E4BF9C18D00305EC359BD91F9FAF76F4602156C30D4C0D4AFD0536906AE90889767B96B5486CBBD4CA8C23EB19B7BFE6A4E8982F0303DEB86D3599CFDB074139836AF6AA7A43BC76A803F96DD48AAEBBDC215DFA70D60338D4ACB8FB9AD319E9C548589E45B2AAA84A714C6ACC3F95B25054E4154F617FF36593460A4D07632770C60745625EE909F4F7B81D734ED5F0B4B7CC25EFD70CFAB919491847B2421FDC8B93B28A089FE29F7B972071935A3F5736768FB38DB9622D142C74157DBAF8C555939D0AF4729F1C61B13444A2F850816F41D451D1A7B100F9262B45B89DFF561FD401FFBE60F8DE04BCD239CAC397DD969E237C9560AE88326439CFF5DA2819200CFF9A327445760B75239189ACA94E4E3545DCCF0587991AA2ADED345660AAFA46FAB9093709768BB6CF7DAC4A124AB1C13BA52DF3EF885E38B36849C1F51A52EC8E232A76886778C503DE0C39F840A6D75B5AE0C215D646586C09BA8A700B52D4C8AA08EFFBA1EA8E07562"
        ).unwrap();

        let h = Integer::from_hexa_string(
            "0x2C429FD1DA672C65E0A091B31376D36456EF4ADC88701DCDB92D280BA0F82310276C0BE96016FB69B60264BA20DEDBC44262A58D470CE184424DBC77D5AAE582D51FB3B30AF5D32ECD6C88A0C9867400C74968714629D329C454A86CB62067E6CF856D8B5CF7683CC000BCCADB64BF88E4E82BC454433FA180F1EFEA19873D41C0C3B503A0F4E94451BAC700B67616FB9812EF05FAAC70C435E9A045BE36A5B989901AA97B4CDF9BC411F580ECE534983CBE19FAE7DE38C477000EA1CC7171708E9A2B4F2020CF43DAC779AE764768FE06F88207C79274C33BEA861FD12BA577CD4601336DB2DB01FA9FED284BE10F8FACE7D840A5AF93947B5DE3001C77487548F71B7BC9FB555BEBEFB9CB22892A3D1108036F5BE92CFE310620C0779FB8556AD523A5F5975EC440E1BF21A302ED446185F93FF81D575878347985B52126E878C4E1373ADDD446D9881E8A28AD0C879BAEF2A0BA6A24269477E42EF9E7D9A5A64CDFC5CFDDECC2F0DE5787ECD2250B4BBAD9C3424501258B3F48D9DD2DEB05"
        ).unwrap();
        let h_prime = Integer::from_hexa_string(
            "0x9E87747FEBFA3B77328A8C18AE446C0CF19563495F2AAF0FB880FC38588660E0FE48720A6F13DFCD7B20BA576662E8B87CE87A45DF61903F730583B76105DDB108C3FA7F5C1DF515DF8714F64893DA16626DB2480CC01564030BA80FF618723B9A9938695CE556209479AC23D3E05AC4344358E0F203AF692EA86A8C7EB6C2FFEA541BA973814D265214106742DB6C39BBEE274D6BF4EC9EDFE442BF728F104F24DEADE4508C95C94D67B9A4E7D8F043D0E11E6F26BD6D2A4A2ED583C0FA185139F1740CD1738442B50A65FBDF3AC5C7173D023486743AE6CC7D96CBDC5D4970488DAACD9F31C92A70900F8DD885DAA76CA9FD5350B956859D7A58FB4AF867AF4AFC1ACA53E71905C455F292735BF34BE0BF9A9B12BC5EC45464884729A48B9A0A1C390F8681D2CC8D4B3010C6825AFA4221BE06C9D2B90B2745E73B65C91658CD1DB39E79381663E9DF1CEA8DCAE6D32407D5F7383B328A85A68FFF067154A4B4B50DF2D39234E45A397928B1B100A82549F6D2090CB5C6FCB2BC002063F42D"
        ).unwrap();

        let e = Integer::from_hexa_string(
            "0x3ABC15411DF0F7CE4B2E71ABBE1F8F6AA0D8CD5E67F63CF45AB47EE75EE809EA",
        )
        .unwrap();

        let z_0 = Integer::from_hexa_string(
            "0x45066332A8383837FA7A67B5D9845185A2683C4BD7B741559F4F3B8D648573D5EB409B2A1C653037281B38946E50CCE2BA03DFEB8A13A6D5B60082AE5E95A07F3FDFD425A9FB5071BB7C389E57802B99D7D86FFE9D0562B3227E4B6620C72D8321909A747DD6471A66F3EC130DB385263CE5CFD494296E8AC3AE07CE1163F630C92F623CB0E2C68B46BE888FF6416BDDC6889F4E3F49BE2BEEF862092AB377A4BA07B29108B11F56366FBE72279A26742E8C9AF9CEE25A724A7BFD8AC53083931DEA34739741D4B34A3B583AD49440F5506DB5B9C64636E55B6474C83558BC7DAD5FC79A7F489166FD846995989077571324A15BF085CE1615CDB9B18AC22DC302D0C716CF7E53B0091323F8694423F3099BB31711E5B7782176F09FB0F522EF73296D93227F3D5A17D316099B3CE9BF847B12C631CA0E2445FC6DA8469143AF4D104B965CBB5859F04B7FB6A562B6216A547B0B8334203AB6D9C808E93D679389ED7BBBCA13049225DBF73D82485ACE0F5B56B9254DFCA9FF6755A95FCC5458"
        ).unwrap();
        let z_1 = Integer::from_hexa_string(
            "0x4FE4B93F9899E3FA357ADDEA22FC871E3E0F746E29C79626FC2007AE2FB6FC4B6871953D73675CE7315CB6217F9231200E026FEE0B845DDD8A98093D1F526C105B9C2778B784FD0D485D32D37DDCBE7ECC92D702A0AC73A75C2BFBE721B34E1F6093C37781044BFC1824B4973D4E3399FCF0C65A5B5299F9FAD3A7A5002F428762A6AF34DCC81EC7BC2D9E46281AB8F54FC1034B04DAAC71C6DD2B6191819FCB29ED338575055085245BE2DE91F59455FBAA4DEA8378C43E31390E6598BABED61D0C9513697D19C091946C0F9999B13AF0DA9D280822CACA9B118D4D28C67799360AFE882AE17792E6C85863D04DE301540AED1A09648B7C48C9A99B7267DE8BE27B178EEBF659D0029AEA1BC95A91F4C2CFEA307B4E621C2FE0AD4A6AF8106F374F695B313D84D48981F52EFDF14BD529C37CD8BDC141746A63333D9A2C3386C36ECC4377C1DA79962E74420A9D67640024087396DC00003494738B83942DBEC93E6424D11809CF09B214FF355E1A5A071A19880C02C2D80C19E5DA588D7139"
        ).unwrap();

        let res = verify_plaintext_equality(
            &EncryptionParameters::from((&p, &q, &g)),
            (&c_0, &c_1),
            (&c_prime_0, &c_prime_1),
            &h,
            &h_prime,
            (&e, (&z_0, &z_1)),
            &[],
        );
        assert!(res.is_ok());
        assert!(res.unwrap());
    }

    #[test]
    fn test_verify_plaintext_equality_2() {
        let p = Integer::from_hexa_string(
            "0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF324E7738926CFBE5F4BF8D8D8C31D763DA06C80ABB1185EB4F7C7B5757F5958490CFD47D7C19BB42158D9554F7B46BCED55C4D79FD5F24D6613C31C3839A2DDF8A9A276BCFBFA1C877C56284DAB79CD4C2B3293D20E9E5EAF02AC60ACC93ED874422A52ECB238FEEE5AB6ADD835FD1A0753D0A8F78E537D2B95BB79D8DCAEC642C1E9F23B829B5C2780BF38737DF8BB300D01334A0D0BD8645CBFA73A6160FFE393C48CBBBCA060F0FF8EC6D31BEB5CCEED7F2F0BB088017163BC60DF45A0ECB1BCD289B06CBBFEA21AD08E1847F3F7378D56CED94640D6EF0D3D37BE67008E186D1BF275B9B241DEB64749A47DFDFB96632C3EB061B6472BBF84C26144E49C2D04C324EF10DE513D3F5114B8B5D374D93CB8879C7D52FFD72BA0AAE7277DA7BA1B4AF1488D8E836AF14865E6C37AB6876FE690B571121382AF341AFE94F77BCF06C83B8FF5675F0979074AD9A787BC5B9BD4B0C5937D3EDE4C3A79396419CD7"
        ).unwrap();
        let q = Integer::from_hexa_string(
            "0x5BF0A8B1457695355FB8AC404E7A79E3B1738B079C5A6D2B53C26C8228C867F799273B9C49367DF2FA5FC6C6C618EBB1ED0364055D88C2F5A7BE3DABABFACAC24867EA3EBE0CDDA10AC6CAAA7BDA35E76AAE26BCFEAF926B309E18E1C1CD16EFC54D13B5E7DFD0E43BE2B1426D5BCE6A6159949E9074F2F5781563056649F6C3A21152976591C7F772D5B56EC1AFE8D03A9E8547BC729BE95CADDBCEC6E57632160F4F91DC14DAE13C05F9C39BEFC5D98068099A50685EC322E5FD39D30B07FF1C9E2465DDE5030787FC763698DF5AE6776BF9785D84400B8B1DE306FA2D07658DE6944D8365DFF510D68470C23F9FB9BC6AB676CA3206B77869E9BDF3380470C368DF93ADCD920EF5B23A4D23EFEFDCB31961F5830DB2395DFC26130A2724E1682619277886F289E9FA88A5C5AE9BA6C9E5C43CE3EA97FEB95D0557393BED3DD0DA578A446C741B578A432F361BD5B43B7F3485AB88909C1579A0D7F4A7BBDE783641DC7FAB3AF84BC83A56CD3C3DE2DCDEA5862C9BE9F6F261D3C9CB20CE6B"
        ).unwrap();
        let g = Integer::from_hexa_string("0x4").unwrap();
        let c_0 = Integer::from_hexa_string(
            "0x561B5D54A74294FF81373E661DBAD5DE5FAFB932DCE9929FEAFFB24ED0F38E1F752FB2464A45AA5F772E80330643D8A71BA43E4552A0C651CBA71D709BF46837A794B59258480AEAFF569BA2E9055388E0AE377F5CCDB211FDF22965D7C01D60720B3AD0E54D4791E578A9A4EEF9D051274E22A04530D64FC717536CC0089D70B4E7BCE03B4532B4CC0584EC60197B03B32E5F701A761F5D97ABC1A4ACC91CB6E334144EC274CB092F026FFDD99307340E6E2B3794B0997C9E14F27CC04530D7CF0F6AD51286794C7696622C955ED3780F3C8F7D4D671EC4FB13FA99A137C885CD175D277E25E6D41231898E150BB4DD2E9CBE665F5DCFB4D2D0A30C9132C9055025084AE2E41BF4990EF91BD74F407A5C48A430FB9BABE371D8A8D453A9580B8D5B9C92CDE1B20F3E868D4A55AF424015B9F3D205991C0FE92C1ABB2692E00A0EBD7C654FC65FD2FCE914550D587E11658B6EC0AB47F7A5F919578D49CAAF45A0770784B3544017AA6B17B55C696DD5EDEACC8B3888FA3BEEF9522366FDBC9"
        ).unwrap();
        let c_1 = Integer::from_hexa_string(
            "0x426F91D279D219D983C3D2927D5CA70C80EDC481E88A77FF5148F4A6B2C1563A3E7664A1301B9EB8223A887E976220A4803466FEBB8F418FF65E62C3864CE7422A833335AA379B02BE82AD375CACC0C870B767CA51150E89B0A4CE7DE4BCEFD650DA3FCD39A2D823554C32B8AABBCB4C7F92C60DAD6646D6C92F82177E87C646BA1E549C7FD6DC212B052EE5FFFE45D2438CC2C3D19C1545473C87F12A35635F3A4551305CD518AF2DF9F8541846807E13140CE49D4C42B7852D007556CC812AADB2631105FE3132972EF50053EA28893C9041940A66559E2B9561F84C1F29AC48C5B324BB4A2CA77639FF186EDF32FB23771661B16628D5F81BE3D467B328EEF07B0409575E0E6111BF9C3B523266D7C59E0BA14728B88FDA10737F90AA87C984C24F60EE7C8B6ACFD6B10B8B60B78E52F30303995E362135797F1CF1C1F22E7F0A0BC2DCFC9C7AA8A127078977A5C96C64CE159907A9E35EAADEBB53D546FD91863AB9F103EAA63BD7B0C103949CD100E71BA705EA7F1F5C726F23A05306E1"
        ).unwrap();

        let c_prime_0 = Integer::from_hexa_string(
            "0x333FD384602A7CBF2A2263B407DB5B56FA264E9DDA6830E60E0826CF81AF887AC466A6957E7A1070F4E56C31025B6711821CAA2189BC6F7537EAB2840ED562AC864420CE1033C00799488201B24602B2A2749DEAAF969F627F04585B7ADCF7E2E17ABF6B97243736F3B8A261344CD5679972766BB3EFD2D7ECA41B6525A481795BEB094259C6559443201E3FA475534E39013278EE52BA440ED64E143704A49BAB0D88DFAB6769D20D461B5ACB359EEA8655DBCF411EB5B1FABED74EF4F615A652E086622E15477DCF07255D41A73EF0ECB69459C71628FE1ADBBC7A2983AB2E7D0040AFDFE0B27E4740A9228894D056514AB1F03A372AAAF7040158C903E55945BC43F5D54EA75868F355CE8C3F74527016FF49533D8954B82A675911BCF4D1F80DF8A1EC016F45456FB0AC24927D8526E11177CFBDCAB6AD53ACCE7B46BFE73CD49B5D9E5BD3237BA632811E0D1AFC69698F4637A48441356E031F21449EF96B42A22073A49A3BE9515E346121395AF9C99146ECE32243E0B6739A38143E56"
        ).unwrap();
        let c_prime_1 = Integer::from_hexa_string(
            "0x1BF77901886682C002A82667959E44DBC13D335F7CD26BF1E5122190830B5A49622F3A2C8B5F72B8F61CEB476A4046E54F6666B354072C0D1E78C622E93F05ECB76B6F19633A3B172AB71F31395DE91F950D2A6B072CB2F6D2629F70F7EDE28868C41B50D6D8F7238AF88755019DAAFEA1A79E570BCD1E5AEC1FFD5DA98093234F1210C3AE5DF7F50C1F6E618DF799D5CB9DEE6E5E053651275E51EDEB3AD03947CDD1C8610ECE5F586EFCA3A4A61C6CC14D61F1B13BBC4D9C0F346594306C0E6B57255FBF852864FF17B7D7356577C58304895268FCDE6D596CAD8F3C946C6925FE0506B7A50F01630CC1B2052F7469CBFEEC0921EFCA66C9595F281AF2480B4F0B507707941DA6A0249C5D1E8DA4AAE6B652E3DA0567449304530AD78A467EBE70D27A40EEB63F318489C6594EF69E4D6E5DD8C440B24F82532581960FE6797F45DAA083D6E631DBDCFE5BE4842E261EE25A9363D07050A48050484D82A5467D6EC69FF1405DB1844909780EB5DEA96B33C42ED0714C43DAE72EB75B1B270C"
        ).unwrap();

        let h = Integer::from_hexa_string(
            "0x166ED01F2651C0159BF1B041EAA5485A8702BD89E217ED1174AA8A7AD1DAA42782B99C3C7BDE26C2499ACBD35AAAFAE40ED6628BA25D2AD0653B88F5F02674BFCC13D9BBFBC8D3C32E38ED45B3484B414B7D14BCCDB83990C4DA85FFABB2A0A8F0389CC07B6C3E974B64E56E55C3FA1ABABEDE5727BAC7B4EEB2EAFCA1D20B546C774ACD44A53C30D6E8A2A8C2933C4E257F9ABF32C91CC0A87F601EE12DA1D1F3BB3503B5D919CD3214F9C7AA67F28B03DA1D9E481ABDECCC649AAAC37CEA954AEC789A203BD6EEF5CE8E3848D6883A97B0AEE0633D16D875381FE7BB261E6A49D1DA266CBCDEECE1AAC5FF136CD86E8171C386D2FBCB47BEDE90715EE226E460A8C10A12332E0CD3AB110A6344C1B1E37CC45E88F109EACAD8C0BC561E8387493A27BF5986B16F966533C09E5667E31D558653AB4854A33F1ECFEF59D7E9EA875C45C0C9A82ED6CC0747EBD21A3BEBB2517C27D4CCF883426E7059FDCD528A5E7D772308F6EDB20C7877487B4D4509EAFF668637F1830C0A528FFE0271A93C"
        ).unwrap();
        let h_prime = Integer::from_hexa_string(
            "0x6C463774F674F20FE4FA0C146D9BB3DC938E234A77045EF599437899BE6987994C4311400DF24F6256861995D73D5A9F45D07946C4F7D3FE495CB0EB7E8E04AED8CD917D16BEFCAD57AC6EABD11F6D01097F7F229A508BFB76803FF8FDCA86605117B06AB6E0632D3B2C3C595ACA8527F1FC28CD64E946F0C7297CC52D4A8CFC2B880BD98665E8A01B540CA8EA9D57AE99C7F019DB3912F519FDF6C9FD33F8684ECD8E33E5A39810FC55C137D2CEB928EA96435C04FFBAFD8B7BDA3B442062A6527DB4F193D1C2EE364BEF94E11DF6A39EDE93F5944081615CBB8F0F12ECDEF4EC09EBFC1506D72ED22DB7615E00E080F642CC6EDB3454BADD6FC4B4AD530CD6D006EDE5019EC6FAAB979847406F7FF2F275D85CB611E2161657A3245A3C831B9857C64A434AE332AF13EBBFD28771EC051586F00A94E241C66FC6AADD015FDE2FE20596C37BE28A974FA71ABF713B085B8459DF99F5119C543881521CA93C01EF79C3AF822041E3FC825B0689F71FA9FFCEDAA6E6A8FFDB28030648E1F6F083"
        ).unwrap();

        let e = Integer::from_hexa_string(
            "0x513F79DF97975847E15EC558A54D1BA83A27648CC1C22B51A03211C9F24B1E94",
        )
        .unwrap();

        let z_0 = Integer::from_hexa_string(
            "0x4CAFDF2FCE70CC3179E88BD8F12A13FF3B9DA0D32BF303FBF078ADA00D6EDCC2E0A75DD6D6794B3B0C29D2AEED8B3C2AC516FBE3E9184BBE18EED9BC86D15310230F1A4FA9A75695E230E1E440D3DCBEDBCB26A3297EA8602CA5A313BE06C5D4BBFA7467CF3950291136B75FD00543529E79518D09ADAFD57B64F336F8A5CB50B713E0D7E521CDCB1541F8C7381001A4BA7078AF1386593000B9A0B8448A10932F61E7D95768626709E7643C0BA166A138F32F8771B84D7EE03059D7F893DC3E7B7DE509E7EB63C917B502DEE29108CC67E3D4E272480BAF09404D072D44BC1E81DC00EA270A22FDB597AB9BB54B3A5BABF1A23F0A304A461F96CFE2BF55209F82E6C66DCC4418E709D7E3B653555F123F2891C63773912AC2366761A6883C3022DB2410D085BCEDE5A38E0506F2BBB1F7B5E02549CBDAE3899ECAC26FAD91BBAD10BADC2E69CA1BFFA33445A6589F23A5620042C7876BDA6B897DBBCA15B0FE284B76645F9C886E62158051299517AB6CBD6E6E24CDCF3B3F08CFCEDAA54A0D"
        ).unwrap();
        let z_1 = Integer::from_hexa_string(
            "0x1589570C326F903ABA701A9C360E23E56400C4735DEFF070F6119D0DF47C160B0F39164E088D6BBFF8278192ED4AF6986AD11C67BBB6D2D863C22BF9CD224DF469420A207D3313F92BDFBF73B5C72F4A589965DA6DABC04E20878FFDF8308994505ECDA9D0FF9BA9682CF6729976F23DA1D7B01022A3E9D2EE29D466756AB91B031434F6D5B483F85F321D43B1CEDBCC27485CEC8AAEB66F5A3E7935E68059ADEF80CC759B01586215F5D1824C6FE4E5FC1E5CE38BB081B9D25AE07EA9D5EE6D6132FCBE4CF1227907BE2F4B015B1A8CEA335AC1D58E9510C4BA92A64806CF4500BA08A284E79CFD4A0B844E04B672AA945E7D21E351C4B2054722018DFB60E26E8BEAA2752F4F90B5BA69D1DC7C3FD3C4CB4CDAF3EC43DCFFA79497BF551513809376FCB819D2A5A4701D1593483490D704C89F023DCE9DEE4DBBFFA690A1BA7B2B4E18956BCCB2E60191F4B1DAEEBCC8E657532BB55BB6C20A3AD2D9585C5ED946D9B7C09422457F9AB0F037DC57BEAFC9A2CEA935E36164E0B8DF2DD96DC3"
        ).unwrap();

        let res = verify_plaintext_equality(
            &EncryptionParameters::from((&p, &q, &g)),
            (&c_0, &c_1),
            (&c_prime_0, &c_prime_1),
            &h,
            &h_prime,
            (&e, (&z_0, &z_1)),
            &[
                "Test string 0".to_string(),
                "Test string 1".to_string(),
                "Test string 2".to_string(),
                "Test string 3".to_string(),
            ],
        );
        assert!(res.is_ok());
        assert!(res.unwrap());
    }
}
