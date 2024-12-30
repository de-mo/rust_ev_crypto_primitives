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
    elgamal::Ciphertext, elgamal::EncryptionParameters, HashError, HashableMessage, Integer,
    OperationsTrait, RecursiveHashTrait,
};

use super::ZeroKnowledgeProofError;

// Enum representing the errors in zero knowledge proofs
#[derive(Error, Debug)]
pub enum DecryptionProofError {
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
    #[error("l must be positive")]
    LPositive(usize),
    #[error(transparent)]
    HashError(#[from] HashError),
}

fn compute_phi_decryption(
    ep: &EncryptionParameters,
    pre_images: &[Integer],
    base: &Integer,
) -> Vec<Integer> {
    pre_images
        .iter()
        .map(|x| ep.g().mod_exponentiate(x, ep.p()))
        .chain(pre_images.iter().map(|x| base.mod_exponentiate(x, ep.p())))
        .collect()
}

pub fn verify_decryption(
    ep: &EncryptionParameters,
    upper_c: &Ciphertext,
    pks: &[Integer],
    ms: &[Integer],
    i_aux: &[String],
    (e, zs): (&Integer, &[Integer]),
) -> Result<bool, ZeroKnowledgeProofError> {
    verify_decryption_impl(ep, upper_c, pks, ms, i_aux, (e, zs))
        .map_err(ZeroKnowledgeProofError::DecryptionProofError)
}

fn verify_decryption_impl(
    ep: &EncryptionParameters,
    upper_c: &Ciphertext,
    pks: &[Integer],
    ms: &[Integer],
    i_aux: &[String],
    (e, zs): (&Integer, &[Integer]),
) -> Result<bool, DecryptionProofError> {
    let l = upper_c.phis.len();
    let k = pks.len();
    if l == 0 {
        return Err(DecryptionProofError::LPositive(l));
    }
    if l != ms.len() {
        return Err(DecryptionProofError::LNotCorrectForM(ms.len(), l));
    }
    if l != zs.len() {
        return Err(DecryptionProofError::LNotCorrectForZ(zs.len(), l));
    }
    if l > k {
        return Err(DecryptionProofError::LSmallerOrEqualK(l, k));
    }
    let xs = compute_phi_decryption(ep, zs, &upper_c.gamma);
    let fs = vec![ep.p(), ep.q(), ep.g(), &upper_c.gamma];
    let ys: Vec<Integer> = pks
        .iter()
        .take(l)
        .cloned()
        .chain(
            upper_c
                .phis
                .iter()
                .zip(ms.iter())
                .map(|(phi, m)| phi.mod_divide(m, ep.p())),
        )
        .collect();
    let c_primes: Vec<Integer> = xs
        .iter()
        .zip(ys.iter())
        .map(|(x, y)| x.mod_multiply(&y.mod_exponentiate(e, ep.p()).mod_inverse(ep.p()), ep.p()))
        .collect();
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
    .map_err(DecryptionProofError::HashError)?
    .into_integer();
    Ok(&e_prime == e)
}

#[cfg(test)]
mod test {
    use crate::{DecodeTrait, Hexa};

    use super::*;

    #[test]
    fn test_compute_phi_decryption() {
        let (p, q, g) = (Integer::from(27), Integer::from(7), Integer::from(2));
        let res = compute_phi_decryption(
            &EncryptionParameters::from((&p, &q, &g)),
            &[Integer::from(3), Integer::from(5)],
            &Integer::from(13),
        );
        assert_eq!(
            res,
            [
                Integer::from(8),
                Integer::from(5),
                Integer::from(10),
                Integer::from(16),
            ]
        )
    }

    #[test]
    fn test_verify_decr_3072_2() {
        let p = Integer::from_hexa_string(
            "0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF324E7738926CFBE5F4BF8D8D8C31D763DA06C80ABB1185EB4F7C7B5757F5958490CFD47D7C19BB42158D9554F7B46BCED55C4D79FD5F24D6613C31C3839A2DDF8A9A276BCFBFA1C877C56284DAB79CD4C2B3293D20E9E5EAF02AC60ACC93ED874422A52ECB238FEEE5AB6ADD835FD1A0753D0A8F78E537D2B95BB79D8DCAEC642C1E9F23B829B5C2780BF38737DF8BB300D01334A0D0BD8645CBFA73A6160FFE393C48CBBBCA060F0FF8EC6D31BEB5CCEED7F2F0BB088017163BC60DF45A0ECB1BCD289B06CBBFEA21AD08E1847F3F7378D56CED94640D6EF0D3D37BE67008E186D1BF275B9B241DEB64749A47DFDFB96632C3EB061B6472BBF84C26144E49C2D04C324EF10DE513D3F5114B8B5D374D93CB8879C7D52FFD72BA0AAE7277DA7BA1B4AF1488D8E836AF14865E6C37AB6876FE690B571121382AF341AFE94F77BCF06C83B8FF5675F0979074AD9A787BC5B9BD4B0C5937D3EDE4C3A79396419CD7"
        ).unwrap();
        let q = Integer::from_hexa_string(
            "0x5BF0A8B1457695355FB8AC404E7A79E3B1738B079C5A6D2B53C26C8228C867F799273B9C49367DF2FA5FC6C6C618EBB1ED0364055D88C2F5A7BE3DABABFACAC24867EA3EBE0CDDA10AC6CAAA7BDA35E76AAE26BCFEAF926B309E18E1C1CD16EFC54D13B5E7DFD0E43BE2B1426D5BCE6A6159949E9074F2F5781563056649F6C3A21152976591C7F772D5B56EC1AFE8D03A9E8547BC729BE95CADDBCEC6E57632160F4F91DC14DAE13C05F9C39BEFC5D98068099A50685EC322E5FD39D30B07FF1C9E2465DDE5030787FC763698DF5AE6776BF9785D84400B8B1DE306FA2D07658DE6944D8365DFF510D68470C23F9FB9BC6AB676CA3206B77869E9BDF3380470C368DF93ADCD920EF5B23A4D23EFEFDCB31961F5830DB2395DFC26130A2724E1682619277886F289E9FA88A5C5AE9BA6C9E5C43CE3EA97FEB95D0557393BED3DD0DA578A446C741B578A432F361BD5B43B7F3485AB88909C1579A0D7F4A7BBDE783641DC7FAB3AF84BC83A56CD3C3DE2DCDEA5862C9BE9F6F261D3C9CB20CE6B"
        ).unwrap();
        let g = Integer::from_hexa_string("0x4").unwrap();
        let gamma = Integer::from_hexa_string(
            "0x8CDA70643AAE36582081C47DD03222D91C8E98532E08A0DA89AF51E2F3AD17FD86760CC4F6CD8C7499CAA487E8C90201B20819FEF31E7D4B9B520594367A2CDB850B4931D0E427140AA9A304AB9DBFDB05A828973C9B7BFF189309B1D7F27A597EB0E70D85C795B174D34658AB1030813D9DE3EEE1D50C5240D1D412A889FBEDD2E55316F11CA054524BDF166BD9EA2E96CCD229FBE5BEC1CF2EADF1D30EF69536E06EC320C83291395111AEA8C21A301B0F23221BE04680AC7D8781DDB98F9321345AA55F394CF1481CFD39A3032A6DACA4606148F3B50A1D3E5AF58EEFDF72B253A5E7F8ED2B071BA8A95F66888223841079D8D3D8D717AC1C400D0F5A3C11E6ED6FFA5ADD48597506502388AA08D2498B2B537FBDA4BCD54EAE650BDB382BCE02E2EC321B05F793CEA1DCF164E4CFA7B9D4787F52F929B1362E3C2103A14AC61936F4352FFC4D5D894891AFA7E1186B41B41FC9D10230E0DFF2B9F9C9F6E13CFCB147B960CD7ACDE9773C06B41119679BEBF959CEDFBA6C0ABD4579CF0DBC"
        ).unwrap();
        let phis: Vec<Integer> = [
            "0x186C336F6C6DF62A460B81ED12D0F39D2E5AB618476054CE78CD3A46F1C0AFD99BE4BA91585C3AAF1BCCEEEEBA0043557DF59C19B196A1E98E984A68CA4661C97697E58E5CECDBA75A6A176E4517B89095D0F6C586E0213E3119F9EADFAE890406F4D0E815FD66481B7C494D5363C8E79C10233DC563B917A879882FD121FE8C898703102E27CBDD93C3BCDC45A915789E51B8724912B1887FE2976B3B12CE7C54AAE4F8935B44691F8A1633432EB3B74F162DC2C4E53C2D192EE12D1D63B11FFE4A388C125624783B9774E0ABD01270A776DD73C6621C1C2023968EB06608F2EEE2DBAB1AE82DB2B89D46FD008F47F92BAE0EBE26198858634DF08EC10F5758B80A19EEFC68CB551FAAF83585BD4B9D69CA1BD302861C13E626A035733A67FCB9B5C454553560BB835051AA71E3DCDDAD79CF0A071D0F2F0844684E934C17AE444216B98DD8330B2CA61498ECF0BECF1F6F7FCEEB74A351995459C5BCD2A9AD37A81B6D61D748FE2C671ECED0B59AC2A8E527810394B0598BADA3E0EABA82F",
            "0x88C71D20829B290F116A70689B971B149F13B511EC66AD3370853DF57CFB6C6868CA182DAC08D57AAFB03998BED3D080453D26FD6DE0B59C3EEBE2B88FE5CD06774C68236304AF897CC82C30DE205529A123450AF201B68E10DCC8EFAE6A1FBDA1EF6FD83D2BC84CED397355B53466A7D3901253356CD567D5108B09DCD2A3529F053466BFDCC186D965E79136FD77116FCEDBC9A6B581EE91EABA5125D5F509526E4F0046272D24A17CB903D351BBB978E81266FAD45A380DF0165555057671BAEFBC3443754676E49E5BC2AC7743BF46D2BE716852EE87F25E7A1A44D54573D8675BA4F02FA7FFBF283B161383C9125CCB00921F3FA7DF362732C2930C920DE76330249B281388D2E0AE9982D9E21070D555E7753E4B94F7F8DFDC7DDE9A2763D4D437742FEDBDC4FF12262C8E332ACBDCDF7D938FC20DA5953A335597BA8B0F6649094BC334957A736CA1564D43784AE761AE7C44686710CD6CF2068AEEF30D894A86C2C5CBA398A6365E84E18EAACA88AD3A3B65B926BC7104AFDF7F1083",
        ]
            .iter()
            .map(|s| Integer::from_hexa_string(s).unwrap())
            .collect();
        let pks: Vec<Integer> = [
            "0x31CBC1D53E330053132B5656E38104A652EC908EA645B5FE378F3073FF45328DCAC8754E0680CC5431A3D965B86B4FB63EC6C96B628EF679ECFAD8C11759BAFC6D19537F3CB070C1635E76E122E5B29CB23D79FFA96D509CC586968837CDF8BDF7341CF569E0C4DCCB8174AFFF2D1738685E529ED8CFC545B0E5B4DF93727DB125B0ABBF29206EDA8B57A51D46D605D75B77553F7B36F4C319A25AFAB8B04F99B4FA5DABCC8E3AD997CD3136DF95696CB6D03B6F2989AD71FAE5DCC7D5F7ABA6C9FBC0B6A5E649A4A9F4BC31F44DBBCEF3A65DF765A71BCCCAE824485211AF5DC59F09E5B833659A9FB422152B08AE0FE33FA9DB708FB133484E79C7E59D2C9E94ADD13804A14144F439CD385623A2AF727194D641A3FE3F98DA8BC791FEA46B4D2764C2B28E4AF63E693FE9022A242ADC21AF1C30FA50DD5A95C1A2D3708EFCCF4E3AC650625137E14E437C087AAC0D1821D225DC56E98928664BC15F667CB669C56511ED4BC2755CBCDD8CEF5641E7355F8C9507274A610BD65C4DD1087B97",
            "0x86FF734272FF39E71683E1F0AD978272878F5CBFEDF178FD7BD42CD4C1579DBB1AFC42BEFD72EE3F0FF9FCF924B22F73A36C0EC672FD48B5976F88C995120AA6C889BACFCD1D9AAAAC80066FAFECC63C7F960A15A931BEE74A7F7720600D7A41EFD31EC898CA045AB3090BCFF3CE7DDF1257F0234599D86D45A2327396D547DEEB883AF6AFC4C2C1552B12C99E5ED9B00A1C3455D3DF0773D5F0530944500AFCCE8FED86E541BA425ABE251128F60BB788E64CB23B84A3E95E8C163AC4361F69DAF66474892814F69EB935CD66FDB9EEFF86D7A86882E73EC1EDE84E360697B1791B9F9F9B5D38EC762E8249D9FE29BFC2E619217E4BBC8A60198B9F346157F44FBD50389137EA08FFC7415722300411BC4492C7725F2B116B1033BB8D930AD8A388689109E2D92A4594E78F250E496E1ACD9D36A2E5F42EF5A3EF2B4256F184093BAECAA4FE3C35340F20E080F691588DCB6FD522BC978B4731BF086DD9341E37EFB6C4AF1FB9EF735880D15AC09D63C4B2D5087893717AFA2A1ED4E5A04FEA",
        ]
            .iter()
            .map(|s| Integer::from_hexa_string(s).unwrap())
            .collect();
        let ms: Vec<Integer> = [
            "0xB618D62A765B226C4D12F879591CD28A6C520BE23128AE15932B7C5475443BF459401DD1229FB8FDC3A1E927658C65BF7A4B7AF6F6D4EE8CD88CAE8ADBC370BC3B20F87449BD4AB28F14263F3D5C2307CE0985588DAC7201C23A050530404F7EC7366E86BC186C8DB58B087D2742471D11087E39A41E5BE68786A5D393EF6ACE278E549F55502E035BDE34278F5F0B6521B2C54BD001CC41B99E31CFCFE48F51BE6E43C6C8CD5FD3CB21FA65D4BD6B17B8A8F5E1783A5A13B1130F7062A82CF935C204CB57FCB57A3FD6A03EEB0E6E4EB8B9E9992DFDEFFD9440DDF0E2074F63C17AA9943F5455370C8C890B52A90B104B567D4CA6D63E68DF9132D62BF30CC1020A20506CE16B13DB2DE82C671C50323596CF09DD68CA3D0D9AB0935CC817C5B04480995F6111DD8A6AD21B7259AD01D0641A0DD00A2F0CACB6B1F4793143F441F5BB5E8D1451971C820BE7AE23F032B5E2FA64C0BFAEB25E0A4B78F52E1DFDB6BC742CCF96A6C64C6F458B319ECC36E406864927A0AB78F86827288FD656C2",
            "0x92428C1CAEAFC7AA5F22530E9BC8BD8C4CF7A73016D5281E463AA4A6566A8EECA13E55403F453443BF02E94E939925E8E75C450E994244DAAE96CA2EDF57C756E94AA9129368E07862FFB89287940E3228125CD722EF3B589FAC70DB275A2B3008EB9C2C19C397FA1E051928B8F97700A48F7FE9A2C4CD647C4735CBA64BAF67D3B6940D0D08BD0401791E6AB722726522C590FDE756E2A8C891BE8D4703B26B051B905878940F6B1E6F8183EC594C6708830FCD6A31ED33473E0A9682881B092E3987B6599DD642FA70B17C762F03E1C5028D158FDBAC92510962C797217435CF7DF37D0F2368384B19F4DC96650C6B7002F3D4FF20C8ED80FDC74D4991CC49D66AC56F5FC7A4C34728B6505020EB6BA5239B55FD5043B3D8DCE5B0D931D21D2EED5909871612675F15F5979766F040ED0574F2C19CB45A25C2382C46071BB984A2350811EEA0BC0DAF894DEF45BCD9D0DC13C98E79E975D7068F5671468546DE8EFBDB94B68F645A13E5A2F89B02E05182773B5DD10A1EDB4B92E1BAE3A89A",
        ]
            .iter()
            .map(|s| Integer::from_hexa_string(s).unwrap())
            .collect();
        let e = Integer::from_hexa_string(
            "0x48214C10AE11C59A0ED9DAAA6CBC5890000F952ED83008F9B7205E339AD09E12",
        )
        .unwrap();
        let zs: Vec<Integer> = [
            "0x4D3C41C1128290839577C292F3FC845AF0608317BBEECD19BEB224296ACE603967DC702E36B61DF38C0C68CA35BB29118CA3DA803A78BCEB39B7F5BB7751126C0FB036A3748D6CB2C5FFB4A96D34CFD540C61106E9AA492C752810F7E504700524FB46617B8E9400545265841D1F276986DF67067E1F29CAB3F308C958850E6CE4E059FF72FE75259556D86F70757CABDD4EE8B7362D5B6226DCC167673A11D0D01A9E42C4E9F5CC21E0E6F458AD651F4BD07D65700BDCD2DC723299A9C621A51C13A018EDBCA4291D3B2228A452929D44A2AB3ACFD7780D789182F0E336120BF47F23324C50BC86C7B8861E899FBE23EEADB235A4A859692D269DF85E512A0ABE1A1F99910422AA439E095EC488E467CE409F9C0DCC24417B836517A9F83DC31A268BB8C804F89858644032A0F8754CDD232CBB0851131658326058C46ECE1FCCFE00C6B0BDCBD978E9E931B37842B6CEF1A196AE5B2475992020AD08F44AC1440FA92CAF2AC19FBA0AF7B3F65F3065BF4FF27771D67133A93E9B2C53E3EEA9",
            "0x6D35AB6FC82E8BA7A8F67E1799E8C57BD6D959D29485945B9736CC36C72EC6C970C7F42395FDDBC2068346B300737438327C916F3D3DD03B0A788A1348165ED7142140F6288A84ABB8C6273DE9CF61E2E62B19A52DB62C0DB3C666D5E766393882F3C2C8C538010486824112ABE14E989B061D5EC18DD75738CC3CBC135ED523EF81F2699BC264D28CB8CE78D6CE25BAD80636D838A57AA2636F7D14DDB243F11455C726788EB30CD4711A21DF9A0A8903917F604DFCAF022117D1DC3C718C2A4A7B9E4949B238EA681D1AE323C343B28DA8F4C055E2E401356518466C42208776858801DB7F3D02B32256A4AF5B608D6892811A89AB68262BE6ECA9B8880F5246D1DEE423E844FE108E5492F95E30FF238B45B432C8EBDBA355E677D532624AAC4C2C80F615AD643FE750433450BD0B933197FD3E3353C381FFB55A520075550D1C517DEDD795953ABB99681352E20791D7C5058308A126A3E2C35B1E1C97344D0707054FF8379377B287A9ED8E2A83078CFE6AB19235960F3B1B2F9D4230C",
        ]
            .iter()
            .map(|s| Integer::from_hexa_string(s).unwrap())
            .collect();
        let res = verify_decryption(
            &EncryptionParameters::from((&p, &q, &g)),
            &Ciphertext::from_expanded(&gamma, &phis),
            &pks,
            &ms,
            &[],
            (&e, &zs),
        );
        assert!(res.is_ok());
        assert!(res.unwrap())
    }

    #[test]
    fn test_verify_decr_3072_5() {
        let p = Integer::from_hexa_string(
            "0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF324E7738926CFBE5F4BF8D8D8C31D763DA06C80ABB1185EB4F7C7B5757F5958490CFD47D7C19BB42158D9554F7B46BCED55C4D79FD5F24D6613C31C3839A2DDF8A9A276BCFBFA1C877C56284DAB79CD4C2B3293D20E9E5EAF02AC60ACC93ED874422A52ECB238FEEE5AB6ADD835FD1A0753D0A8F78E537D2B95BB79D8DCAEC642C1E9F23B829B5C2780BF38737DF8BB300D01334A0D0BD8645CBFA73A6160FFE393C48CBBBCA060F0FF8EC6D31BEB5CCEED7F2F0BB088017163BC60DF45A0ECB1BCD289B06CBBFEA21AD08E1847F3F7378D56CED94640D6EF0D3D37BE67008E186D1BF275B9B241DEB64749A47DFDFB96632C3EB061B6472BBF84C26144E49C2D04C324EF10DE513D3F5114B8B5D374D93CB8879C7D52FFD72BA0AAE7277DA7BA1B4AF1488D8E836AF14865E6C37AB6876FE690B571121382AF341AFE94F77BCF06C83B8FF5675F0979074AD9A787BC5B9BD4B0C5937D3EDE4C3A79396419CD7"
        ).unwrap();
        let q = Integer::from_hexa_string(
            "0x5BF0A8B1457695355FB8AC404E7A79E3B1738B079C5A6D2B53C26C8228C867F799273B9C49367DF2FA5FC6C6C618EBB1ED0364055D88C2F5A7BE3DABABFACAC24867EA3EBE0CDDA10AC6CAAA7BDA35E76AAE26BCFEAF926B309E18E1C1CD16EFC54D13B5E7DFD0E43BE2B1426D5BCE6A6159949E9074F2F5781563056649F6C3A21152976591C7F772D5B56EC1AFE8D03A9E8547BC729BE95CADDBCEC6E57632160F4F91DC14DAE13C05F9C39BEFC5D98068099A50685EC322E5FD39D30B07FF1C9E2465DDE5030787FC763698DF5AE6776BF9785D84400B8B1DE306FA2D07658DE6944D8365DFF510D68470C23F9FB9BC6AB676CA3206B77869E9BDF3380470C368DF93ADCD920EF5B23A4D23EFEFDCB31961F5830DB2395DFC26130A2724E1682619277886F289E9FA88A5C5AE9BA6C9E5C43CE3EA97FEB95D0557393BED3DD0DA578A446C741B578A432F361BD5B43B7F3485AB88909C1579A0D7F4A7BBDE783641DC7FAB3AF84BC83A56CD3C3DE2DCDEA5862C9BE9F6F261D3C9CB20CE6B"
        ).unwrap();
        let g = Integer::from_hexa_string("0x4").unwrap();
        let gamma = Integer::from_hexa_string(
            "0x8953A093731FDB3D9935142B6BBB614B1F4325B1747288302FB7F96E94747D6AD66E5377EFEDAE4913A5C4B144C3BBEB952D25C463DAB285A49A72AEF2078E17E39ECA4F32FE5CC40D8A2C13267B128B34FD31DF5B2BFD6FF65A6BF906FE8A6DB3CDA03523A3BBF41440FFBE15C5562915179CB2D5B39D55749EC4D17AE3307A8C4CC13B9A8395213D06B2D7CE2CDD5EE8C0232521B9116783DBF8D21982E71973CC91C4E129591DB73F4975556C7C0B2CED587C4E3E4E1CAD90D720137EF13B08DF293198D1573CECB977AC3B2D3C53DEA8C6DBC5865CD0903D34AAFFD17F0BA98942A8385E138E1BC2FF7E306F3AB81B2C86A54AE3C620843CEDB9537E238DE31514429DEC1399DCFFB541169E40BCB6459D4745F4C794866DA181D947E304ED1A18E0122FEED23E6CE5C2E7C566126D799095292B7510A5CC451F5F5411235DFA7FF1275ACB4EE5F055D2641F3D32CD7F68F09CE24035F214942AF2ED3C030B39FB06D31FEF59CB1C2B37D5A48E89C3075B2AD75D64AF678AAE66CD8CE9CD"
        ).unwrap();
        let phis: Vec<Integer> = [
            "0x9170143C5096588E6B82403A6EF876C7A697D7A09A0A8FBCAB5CD70F26CAB34F99D5E7F71FB4141E3BAA90C9390A87C37C8CAC4808180297579B6BC515A4DCA79A4EF46C0849D63CD307CCEC56D58529D02D1E106FC66DFD759D4FF1D00C6C9563FD292CA5AE420743E50C1DA3444FECD015907FAE379659FD3303A78077F5D7D8081293A9F722F3B3FC210DC47FCC2900013889703295BCCB4951F3A648B25B0449941AB3976A8D1AC1B1F541547573F209B8824DAC0FF0BD69B13C5BB3AE869138E6B077A753F3226171CAD5752854352CA594348BE8781FB0FCF2DE0B5CF34157CC8D2338333F006D08B0602936807BA17619FE50E097DFAF57E472ACA32AE8FB8380702380D220A7602CE82612F4BE871676356DE2AFBED1D5A6464194C57C6F93327BEBC5E86695E384B7D381BFAA136090185300FAC9A9FB8AFCFAC16153953C33DD5A1597C9F885213FA06FF2C74BA346050943025FB4B577ABCECA3982A894DB3FFFF9FD9C406FF827AAD81A75B51A87890A82C23482F2F729BCBF13",
            "0x964F131101F051A551C7BBABF1CDDEAE47CF7E1243EEC41C10487CCC0D0070A8CCE33718EF135A4CDCE5F36897021753D3227835A3F0F1319133F1AE0D8951DEEE9DA191F687F34BBAB2ED2EE82406AF78C8FE1D0DADF4412F0995DD6773ED5F5CF4AD9E32121E4E23CD418A790D993B464E10CF8077264742287D1F9ACA7DF3487FE9881C0FF248F2A36C43CBCC0BC7828645AAD8AB6F9FEA2E701F2BB7C43FC43173D10B469F4D71C412D004153DA9795F33601B4A26BADF19A6AAF85D5956435D7E59BF2AA8F4C64E30BDE5A6054E31DEEC40D401E8898B95D6A32FE3B75AC6063F7665245971B25A45954EBE315C85EDAE8A9E13A445CAA791A97B0A3E0A0D7B958785DC446BA271A9527BF47D200307F2044C8EC0F74FBA759CF95AAFAF3AD87BEF8F1850D33AEFA8E4699787C58DD13AA1B6EA4D48B75FACB263151CE72638F4AEC282E1FC3E47A18E335FE1053E509D4B18D1143289A82F30DA4A7F1474A625663F82A2A30463100959CC21A4EFACAE7954A4E1887952FABEB9B4D029",
            "0x8FF961C5D2B91B53417801654AF010714021260C244BD43D451CFD3299DBFAD3F4810A556FF2121AB935A1A59638850256AE5FC2718E192FB31F6A98E3085A61BA868F663827CBB2296A6BA3C6B0AA3F5DB76CEC913C33B074CA8CFEEBEF11B041759D6E87E87ED1A0C628054F060D89085837626A38E77F1BF0CC86714D4DCB826867103E8AECCCA4212ADB5A5B1D9FFDDB26DCC10F5005D1F706CC03808ABF7B8DC837754876FFC68DB3D2DBD88F34F7C4107787729F310DB7D9EB787EC38D667027DC1D1BC9C32D17B811001E5172C9AC581C983E0D14B02183AB1D56FBEDAEC765DCBF37EBA38A851F0696668E60E529A3F0D834F0466B8120ED9DB8BBA30618003E3D502C3A0E4D81A334D4499DFAE285D2325D542EC5201B8E7A1B0823B392135F321EE3FF1F0DF949A88E4009A7BD24842BE76E2ADEF40228826E432B7D686FD8294CFD9295924777F842E2F5DD8FD4CECC88DA25186F102999D4784A59678A377CAFC46182ACF3C90E1EEF426BA112499C1BDE3E4965953405814B7E",
            "0xF75FE1ED70560FBBA6A8C6A09B53DD2AFB21C837F1E59E6433511903A6FC70F34E907716060EF269D313625B9C66E7AF4465C2B77AB6B829ACAEF247AF2F54FB8007997AAFCE5938723F3DFDB659A09AB8FF505713092C14C4DC8F6D5D21AC4260CBFA24544AE44BDD76B678D4DC72204410409C4D740A5DA67A94AC32CDF83035410CD13BFDF16E218CA223A9EE2EF602D4329576C8293B523292AF53EF44ACF2F4BA28059100E3A89E107EDC4DC25D8E0FC1A8DC2818DC8CD5E7BFC828993F12B0C4D5EF7D3F02D3A57E1C3719A657BD4FB2DD24977911122D6628527ED7D0B1D8A24CBE51CB5A7FC8B9DA37BDF2AB2517552F2F52BC2CB4C3572F6CC674B8C3A3EF6E44A3D198DE275EE670ABFFE0BA5CD158D8E4A26BD8C1372E148B0DC0B046B5EB7256D02116B6AB58B3A9B5D2D07772ED0292FF07AA47D7A78C233ED8820CD21A20927F2DE394D44ED35D7E0C6894069560ACB316CB551B81998E4CDC196E811A6BF41AC6618BA6AF9FFB5624721A73526D6BCA7F1099DADADEC4A75",
            "0x6667C738F5B99D5D1ED86D456776A953C4DB48121B3B36407E8B3184BCAEB2F27A81DA28FE37F6C2199AEC35754AB3EDF00710D8FA2A32673EFE72185DA1B67A19ED1A9F85106D4AE6877FA520C3EBFB3E9B10154D8D301FFBFE70707F9B65AAD812DC4AA838626CD519F4179EC3D5268B704696869BAF31D54105D7622B5304408B8904931E98D9EF85F77E19DC1ADD718F9F0C7E3B55ED5F3373C30B0941FF8C6070DCBCD36963F82D220D2B7D7ED12961DC87DF85B9100ADFEAF72463B2836626C0A3ACD935973D5F62D5B209250AAF631153790D0C338F5088B5BD93EBD8A6C9D496349660288768DB37C75FB12C3628A03073B9ED5166075224496D5ED6C7CF3F55D83A8D951FB31DE9001A8CA289E2FA2E90F083E6FDD30300971068A83A4266F38D7BA323A7F7F1A5582DC7A1C82F2C2D38E90701AF80E2E0438ABC1CDE65B9406FDCDB3DD73CFAED9FCB1958B835AA1902C55147F0B6C57D632E953553115C8FB8CC756B01EB9D268BB2E6157D5A3CDCD0136F241A1959BC3FB98085",
        ]
            .iter()
            .map(|s| Integer::from_hexa_string(s).unwrap())
            .collect();
        let pks: Vec<Integer> = [
            "0x2475C914DA002D0C0112A880AD374C54708BC8801C1C349EA28F199FEED00C67A9B501A88E32DD9CF909D106E5128DE384610119961670C9A267C140E5FF485DAE31F7D0425E0E093945A864CA57C0931D9AA073E97E6F0926DD6511269DCFC2BAA213EB909993385004F2CB6F29CC10A48C8485D98DE605B05D69BCDF59A3658FA712B341F5EC5B083AF9F8ECD3AB2BEAF8FCDF47B51B38AC206E6209A3992B53B33EB6B028F77A8A12170968DE288113BB5FAB0E876CDDF5EE4AFB283AE18E5C2C9CE1A5BA97E6EBDC2A1F1A61C06F0B2EC60B554F3FEF4EAA27BDAC4DB9C3CA2C7550778928781591EFAC8F42906A39FDCF731D34C1E3B62B566A2D453F3D87AB3098F72D2408A676A4A8B7816BD8DAEA1CAFA496B1883CDA868ECFB083F74060EA43429A852C2C79AADBACD776EA5D135EF1C2A80D3E4878E529FD75913236B524D9144735371529B17BC086FED1546B9ECF376793517A2EA1055F1292C9A1EFFE1666912AD8310B0D767B2DABB3F21BA3F9EB68F07027FF228600404A75",
            "0x4AD49ED2EE0B5AE21DB8E8E4DCE4D472EA921B5B806B782672B55CD7ABE3D8ADB53ADE0A39ADB6147DFE806DA443D479824100C7DF28A85205DEA7A0AB425AA3A254CCCAAFB2BA150FF0808970A03A39CA10332F28692ACE786A3CB5AC40BD2EFF6DD1DB44EFADE5955A38E8C720E1EE8FF7D579EEEF6BC813A1200DB3220418137FCA3A2684B864D0D1DAABCBD5E8EBC60075BBAA32CC7600CF9AF9F8CCEFCADD6925B6A51393889A3E6EEA73C46A55CC9835BD33FFB0E546122B0C994237491053DF38ECB3C4BA721902C67E88BA8A7032F8FEEC6EC81B08B9A77BAF88B0FBE42AFB2D52D479A26A4022A1BEA89A008C4EB7EBCA4C4DB9A04F17DEA75F0EE67CD6ED2363B59CA79CB635271BC23273CB8E75AA15603B32CFD4183F87479B68AFC2ACBD42027130A0B3C15746D07EEA067B46E0013F17628EEC981C38BD8DF4BCB10EA3225F5C11F74675CE65951350F16B5039D81D1F7F40F515B9A477A75E41240A0C3B16F69B7DE1BDDF8D730221000F7C6A30F45511D9E935514C6B6DCE",
            "0x4F588CD3E614BF9A61C9E46501E77EB8A37277B213F36EF8128D56A041C0BF7ED8487A774D62C703A2B1E3B494B51E08B4B91DF235E9589F96801BB1E1EC82A7189E02A63E79A2C4D26506BC6DDEA528EBD188B0D34F12DC9CE1D0162AA613CADE54263360A21CC91F6A38307B49E3A0420D9D597AC34F5EC1CD0E58B34BCC1E3BF38A6843DCD1BAE17395C9933C9EAB1B2BA7F3783AB5287DEC4CD596A7BA9625896AD44650DADCAA9D7D21E799705AF72FED67DDC5DD1033025393766B0F509E44E547A0EB0233FDBB2133947C8BFF6A79DF4618EE3F39EA3086EE0C4438610E85C083FA3C0430D2A779E020CC5A20F99695D11B244EADD557B7D916CFBFE78C317958124886D50A573C7A440FC7EAED42F6E62661B663366C8289B2AB83AD88166869A0E821DF1A13ECF24B90EFADBB716A85B3B4B15203DE576BE899D1A56191062BCDCC2A3FD34A9A3C1014CB62CCB775C27CA6152F812C1CFE41336DD2B5D6D50FE7E1CE42D971918658DAD58178991BD0D6C0922B3794641DBB8C40A8",
            "0x8F8F3FB693A2B3E45D596D3BCC4EF2A12D3266DE8ABED17CEFE4C27B66FDE6C707A1F2D850CCDE129656F0618760AEB731CDAAC98CBD1A510CCC8838AF1897C049254406B247DF3A48AD920B6C61D246A533FB330B0613345D0C3EAF8CC7B67D3ABEE867A75924C27D1E0D5AEBFBB251F2B45C183161FB7F726B0E4E8FDDE5F037C303A8CA96D72DCC06B69970FEAEAD0C40F14E329031A877A87EB58A7C66F8FD173019529A158C2A052F251DA12F698E6AD3BE9AD6DE236A1302DC66D136C8CF48D1C54381370F3C70CA3E4B807764E5B8651D8E6C7A3356B9D985FAED55C22BC1D71625C3E2B3D5FE14DF1FE44BAB1EB1AAC1D2B43AC7BE0EC7DF0FC9DC2B2BD0EA66E121A7CBBA63B2CB872BEC1170AA838C84B73F5B7BBAEFCB795281EF92D68DCEA9806DB1883959828E0FDFC6CC4058C489F74739A6BF21CD30E84AE935C5C4690FCB174C134B248933D45228C05FA5D29E6B8C3B189BE8172997040DC20F67435C8D7FE9E5BA086AD672BD120AAE3CA801B289B326CE95774990ABA8",
            "0x788035DF04EE3CC70E805BE33776FFE6CA492787B3FE0515A57823DE624C28857367C8CBF5937BEF8F267DB58775ECDB5594813EA4F14FF836AEA354BA4D432B02B1EDF33BE87B7218B6392B471A5F12A0825860EC107CA89FD20BF3AAD504F0B6B21360F70D480FD0FCA159176E48AC2C951F0D183C7DEE6DDA0841D62E803E38233F3CE1E6F8B77E24B869C91D1190A8706A6E06D23DFC50A290E83D0FB5A33E0F683A3524CE590BE684D2D56ECA75472F6612F681703600CD6AD13229C81D7ECBC892F247BC58EB8156365F5F80B053F7FB0D440DC6D407C3825AE5FAB3C163C777838350B5C120351ABF48718DB5640B8F87CBEEDC8E94506E0A1A726D261A30B101356B8505987BEBB874DC576D497110D4024518BC1579C2DDF811C2ECAD1522A58DE895577EA38531C57605B4F93DCF2631809B25E3C1A66FC0A651A060C05B09F6A271502D63E91C7E87873FFBE035BF7369606413C61859541CA4D76E43971C805FD1B62F14FBD6EA15BD535BF134A3436E409204FF16892BC7DFC0",
        ]
            .iter()
            .map(|s| Integer::from_hexa_string(s).unwrap())
            .collect();
        let ms: Vec<Integer> = [
            "0x82213E5DC4393D13AD40677AC8B1B838C1843E58DC3EE98579E1DFFAEE50311484C8E018DB0A807D0BB8A058ECAD0D35FBBCB38AE83D78C86540CE8CB5262EE8CE5FC74566A8FC46F8FC279F8F0CBB41B45598F480D06EECADD4126333F4B8035F9116254B4C194040A8B869DACF2136CE58A9656D5D39E8EB11D1BEC5842248193428363CEE43688BD455B3DB3E42BFCA5F7120AAD0DFD4466294F2950253EDFE9A2531F161DE18A7503371D7675E29F7021A0ECE1AC787E400801D8DB3F3CF99FAAB47D478EA63C9955804DE8B98A0CC70C912AD31B664662B32ED2838E1A4DD7DEA23E5E08D0881EF42E57F70ED239EA2138491065E2F4E47A728F243231AD2F4CBB65DED705CE014299C58A03462ACC4D35DB33AF359BA362E64390A5F1BC9196E05E23BA306F3193D245D6DFD999031564FC84CB57A1A1C5275A3E4167958AF34474398AAC48AB744A2DA1BD34E14E00834441ED072DD8C801E27A74CEB2A4285C0D50FEE6BC38C59DE4C589D4DC6278955497AF44A4EC90E8D6B20DA2C",
            "0x2C903B9058165DE36B5E9F2C9C2D4D941045619F54EC8590B95B2332A7749FC1C52F18BEFFF7BF6B4BD7626A57F9DD3453992026F36B8AD6F3F4B42C1F239D259F43239BDFE183ECD3C80C5737C0B296387ABA8C56E7D8FB3080494BADD3C87A8AA8E91EAE30DEE23308F9C44D7BE2947B3F011159839474E47AD883A130924BF7E4017EE4540E8ADA1E666168B55C440C63C6C3C0ACAD0FCAA894CB60A4AD12A037C7DEC1B50544112099925397ABFBC1903A7CF2A587ABE1764EA0C65BDDC1718454000FD524D8E04603885075679D1A0F1C6BD54C352EB508EE03FC0545BC55F098B6B6ABBA041BEB3EB360537A7A57A5709513873DF3738ECDC82E8F5BE0C1E160DBCC608D76F8C336BFB684868330D46B9B33A1FD8968F01FE50FAF185881176D12D82C68005B5F82C9D2315C0073DDB3968F69E3B55A52FF12CB4266D7C33354C187A95E15F07010A84DBD990EE05DB530476189DDED7A49B9C73B32F1FC5EA75772B6DB8F0640A74FFD4EF261F74D347B4AA4C2DEF14EF142B9CF50C9",
            "0xAA72A16051E8B6276CC65A462B0CE6846C982A98A6B53791FFE7FEED4777B9198D9000F44B6A9F3A495CBA5930CF96C924C6F1CD30B7FCDB97B605CFB89BD55352CE7A161DD87FE244F21F771A18438EEE35D9E51DF17F1610C081FA18E7BAD654E031BD37A6F0EB463FF79E188E0ACEAE063BAFEA145DDB4EB06FA557B9EDD5F175B468245D4EEA9D24A14F1255DAA31C6A8DDD8C2DFB5A6297AA00C6E1A2B5AA7C151093CFA73664313097D3851AE4173FC59000FE63EEA74CF2B33196055EA59FD92509453A41EBB727FFB0249DE75F16243D7D203407D961F7300FCC48C6412164E5AE4F4A5B120E8C8E4230CFF0F2459BC1F166E1D4A557C34E0D9D56C126BA67E6674708E92840A6FD496901A6DDCD92DC27E874E5424148910026A3CE540FAAC9D260AE70D693396E28AA0E958F2048B97301D056DDDC4976A135A7E5C79850B5982E9D121D14C8B89E3BA688287AD1C70106DD6C1EFB8AAF011C019F4C6E4F8D753F7CDF333B4326B4070895F46971670B182CDB1B0591045B033614",
            "0x6B962A969C0E96AAA6DF8BF8A5A6FBE569FFA98A5C792F533144303EBC9DF972A9B0757E1256350D994AEDFFB3DFE352B876262FA4654EBF90DC636F18E09CA61D450F9D72950B9036ACBBC8701CD27B0DBA75B3273DBE432C73CC083105F68139D8F42F6C0312B7858E1987BE10A5925D64C4EDAF0F77D52EA5F1531BDF7BCBC0BA4FF38E1618156DCC34F57F15AFE5312C2680C3025975126B09F2889D8173A9DB197B45A86BB7643B210E018884BF9B9D5293FB9EF5EE08DFF6FE561BD96443C4E4918BDFB8F1DCBE458868CE780A36E3C570959349CAC26DC452D19DD2744130CD92C1D2424A924C7362883EBC2D20CAEA64CEEE87C36CEE5830BE83FA6325FC075C374393D33521686EE05135C8C681DF44677CFED5E67361888FB2D126C92D0A3C67721F6C186F3E4C5607F781D88C954F50188FAD27E7D0DE1B73C76AC1B6E3C3DE945078AB7ADB0ACEE638E3EECB75C46AF5C4942FA6EDCE8AEC73B75623A78291BF974F39A998679D528DE8B0879CE26029C9B605C7A9FC37DF9286",
            "0x789C34FEE9254BE71AAEC8B2BD9D32B981F2DE6CCF52E670EC3341A4182E3F92E55865BC9CA46280188D5BB7F5C0144A179370A5E7BF837524F89C5E67D910B9D0D1D9113242B7419F6FFF4584D18BBF75C80F49E736FBD5362D19C365822A6FA0D5F281F4C853A177DD799DC4662C8D95F5964E4D73969F0580617611704E316187698752CE831048DAF4983AAEC1B39F452A187A549BE44A09B9CCABBC823BCBDFBB42F1C4F3700F7C836FA566241F988CEC5B9B7149BD222BD8C4972B85D21F8D7550D404706C7AE7086ABDDBA46499C1FD6DE80E40B33CD2E48AFE2D15C2791904DEB7A283FED5B1A30E82C8F71C99339EA0A78D931FA75636542A3E7C3E176500D2B8CE51D9DA8E0255BD191600EDB025A85A1C93BB2796E408B49A19C0CBA84A4D1D739EA39554201B4D99AB131F96272DAFE4D00F71CF3A15B2C56D884BAFB6AE0C0D0BEDC725C7D23F0B7998FF8152E94E07F262DEC6EB42A54228AF242601600DF70C85B2FAC766BEDBE9CC48CD4DC536886C33B9D94A3844F1628",
        ]
            .iter()
            .map(|s| Integer::from_hexa_string(s).unwrap())
            .collect();
        let e = Integer::from_hexa_string(
            "0xBE506CABC7D43E22C754E80AD55D6522ED9F360107F062341AD7E0D143F9145",
        )
        .unwrap();
        let zs: Vec<Integer> = [
            "0x4F157D4189697E2A1848A40EC3DC87C9A7C1E02C3919B23055FBDB25EFDD23F92F785F22D544A3E42E486A482746886E8D41C0B461D087D93D63E371864759CC9320ADBCCD7568623D862F9E81AB0BF80B30551B79DB93819A3F21F0F6EC669F997A3C1F24037EA88680957E049D84B78511784250D24EFB8813FCAE010F86177340AD433DF0853542F3696E1932D6045AA509B6AC1C050720EB5B8EE82E214701263358F25E3ECFA498F970D185C3966D0E6407363D937754C10B9813F2595ED3EC47A32AC2853ED64F3FBAF4DAC78C3CCF06660A107A89C945978ED1D9F3C8F2DDD9739E76BDB66F8747B6F98D4755E4A30970A572FE28558F78772322FFA0703B8D5B9B192637CED8275CEA77EC64CCE58223EC6BEA530004CACCDAA3BD9E845F6F65D52A70016E1C4D41127BB3841516AD42AA4CC1968FC06FCA3A0B04582AFC7978C0803BA55B3CC62636F970BE0B5A3567C1F94DE7A59C29B51BF50D0AB75913301A8F4F2FE7D2F8389455D2E278B46EDAD1177B1A772CE76DDD4E27EE",
            "0xB650FF393A529E05576ACDA135B929282B73FEBCC0CFB6D33C89E8A4F95228353C7FED534626D3DB878A363315C6E0ED7C84C4A35B8717623C630ED9F3FD0A4E266DF2A23A68A89FB417E89E549CD6CA4550607AF5626C311ED2B215E55A2126A985DADA676E10E0EF7CEB861787D53E18B05F917D8736B7C3A686C4A2BB0901189420D8017D192EC0D4AC9D5C43AE99485BE8128AECFB7BE15AE78F0DCF7E3A1FCD3798D2F8307F71B0FBFB52CD8A09391CD91202C47FF4A83B5BF2300193CC0ABD9FAB6016B6D9BEC7EAB2D25034E4AE7D1F28C309A2165862525D7C8E3867293A6D1A3CC8342FC6CE0D8BCB4D4AD01B72949D9E08F583FE20217B3D23B385A0708730C7661B388E59275E5368CA9D99397D9D2BAD4B6F348A1C582F26FF36BAA5BFC492E397E9B76DDB5C6E47521A0E162C4B98EF496A058DE7D63A16ED3D01F0BF230BBEC2F07461FC3C4F6B63D9F923314342DADFA17A6B889E8981F1781CE67E8D009B66FF7D449795E489BA2BDEE9BBE754660A6D5FBBEA0ABA2F639",
            "0x5989C355D5874C88CB45830AE1ED274F5CA1002C21FB4C184DEBD8FA305BE3F78F463E4D913C1F7CDB87B1CF5CA49083850B7CF716833D824D5DDC6242E082402B8943A1D5297CB2EF7C72498C97319B46C51121B02B551C35D127AD64E76A092D42D0B03A0923864DFF9B330A5DDC121C02332CF6C6FC278554227AA60C80461017B159C7A8980C35DF62228623985DDDA6C7C6C1110E32C4DC73B85A98D41048947056D3E3D8A6CAE4745C1C98A9C6B0A0B24167B8DF8379130F794FACF07C0D93E15EA3C924D2DFAE4259D1CBE1E104D7B42846798E0F5C3332D8CCB55231CFF166BF55F09D3C22EDE3C0C733EDEE829AFE7D0EC8AE12D048579E91EF9706578EFA859BD14995395FABF5ED9793D4880C371856609F94ACB0071FE263FCCE900FE69F47D3A05358B77A7CD496B913AE88E4A4C945DB5BE43E9F0D18641A271D118EB21DDC0B6EB7195C8A46351F2E4382F8D6BFAAAF501201EDCA381E3537FD888103EA59EC13BD414252752F5BF63A5248D0C47C8BF4409F7783B28A55A",
            "0x5B713DD6905A18C88FE65BF4DF40D95591FF099B597E30E67C147F3BC436CD07E67DB65F39C53B0F393A25625DD618FE323AFA02B4C4A2F5AE035299CC28B1BD667725ECAF95A13C487F51D4CA193C775BB3B93FFD334611E20917FFEA1C7B96D4D01DFC3C13352C8F29D97E5E8C97372D77B65708C80B831FB6F75DE4914B2E000A49F4CF6FF364BE3398E2F74D274DAC0FCFCA3B0AB39C8EFC7BA86646B8B28F46A65B2BA0F30B88A22200D4A42A8C6AC9CEB131184C00A20FDA9806801B1F5EA6101E9410B4017F4C9C7F8547CA4EB596C79213CEBE288F0D326A070309CB4EA3E990284FF8B58E9A772595B0E369FE9D9D756CAAB5D1B3432C48145E303D8DBEDB5F9A694EFA14F678601E28EA9CFABB2B24886FB7B3E1B751C60AE4B970DF874F130E1660EA2D681E5A96787D5E646F0B93CCC3FD0737832E95F036B29ED972AD5963A3C0403FA49677B8400BE8433727DD2907737EE952560B7F58579A58F99B62A35EE198B24F4AD777F129812FE7DE9709B9F757D36EA088D124B731",
            "0x4A15BA5F4A483D412930FAAFA86E65E21598984FC605AD0DE0077B9AF7533316C4991E4A089EFD418D3B4042AA12F98BE0849E141A7D7CF74434A3FAC7F928BF308C48FA193FB74DA4CF994F7B084DA7D3D08FB4FB37E6A764D3253E79B5EAB9EF568AABF56DC7C8B8839CC4905F6EB2CE35CB6311BCDFEF64C95EB65BECBC9783B767FC378776666C5B59B7EDA08BB33FC0355E3EBE4551181DF495999C4E77906D4A58F6FB5BA3E04363CBE526A58005230CAC71DAB8F0886E921E378DD6B937B8D35A20F7A3F975A73E803BA4023F93E3BD9F33AFD1049F2E0B2252E06C01F0CAE6A5266C4BC2973182341635D6002B82C26D62B3CA5231E3888F9E55DB9F5E04800A14BF53258A9373506B077C0659B27E72C6B46FCC07DF3C952012309FCDB963E268A377EE0AFE04267EF8C1A731C65B9FB12E319F7BB7DC6AF84F255D36E7080B25F105560EC858B1E4DA67A76A90C47F3E385973D1E2D3A5D865B47912D4222F5B6DE49D867F6CFC382955555CAEAF8136D10814E238EAAF1CE6B970",
        ]
            .iter()
            .map(|s| Integer::from_hexa_string(s).unwrap())
            .collect();
        let res = verify_decryption(
            &EncryptionParameters::from((&p, &q, &g)),
            &Ciphertext::from_expanded(&gamma, &phis),
            &pks,
            &ms,
            &[],
            (&e, &zs),
        );
        assert!(res.is_ok());
        assert!(res.unwrap())
    }

    #[test]
    fn test_smaller_ciphertext_as_public_key() {
        let p = Integer::base64_decode(
            "jA4DatkpgfS1r6X1Q5iYA0sS2KakO3pabCF5uww/NyUxmZLOWP1E70Wq1jYs7FMgqAXPvfWn2cCdVGrU5ZcoHWim7FjtyhZPFw15XXewjoOsBUDoqf1Pg5mNakQpQAVEhqMRQ4s5FY1nCB5FvsAUnd8gCONEyIo75r6nj0BmZSoKYCGICT0nBnD0tpW3DwLInQZc5L+x1j39j+CGQI9wCk4+FhAyrK4nNMSsHv3vRUuxdsJber7KZ8d0eqRcyuRZdTbbBDmwz0GlxEmSrP4KRt6gohGN25y7myXQkza1alJpsNOGmBR7GSipM6/gagxRroVzAHBCVNp20g9d7UUZ32DA11pbBrjvEIWMNtZBKGr5Px4d+BJPljxBsbANBqu3d4gfrc5j0Me03yRbPwWq39r5sNFFrIMURmqaOa9l6kVkBBvgDiBt1ult+X787mO6orBoyLXMMCU8qy3zIdzCi5Kfq4Wn8i1C5af7SowhOfV33XNoRnMfPp3CSZaWi1wv"
        ).unwrap();
        let q = Integer::base64_decode(
            "RgcBtWyUwPpa19L6ocxMAaWJbFNSHb0tNhC83YYfm5KYzMlnLH6id6LVaxsWdimQVALn3vrT7OBOqjVqcsuUDrRTdix25Qsni4a8rrvYR0HWAqB0VP6nwczGtSIUoAKiQ1GIocWcisazhA8i32AKTu+QBHGiZEUd819Tx6AzMpUFMBDEBJ6Tgzh6W0rbh4FkToMucl/Y6x7+x/BDIEe4BScfCwgZVlcTmmJWD373oqXYu2EtvV9lM+O6PVIuZXIsupttghzYZ6DS4iTJVn8FI29QUQjG7c5dzZLoSZtatSk02GnDTAo9jJRUmdfwNQYo10K5gDghKm07aQeu9qKM77Bga60tg1x3iELGG2sglDV8n48O/Aknyx4g2NgGg1Xbu8QP1ucx6GPab5Itn4LVb+182Gii1kGKIzVNHNey9SKyAg3wBxA263S2/L9+dzHdUVg0ZFrmGBKeVZb5kO5hRclP1cLT+RahctP9pUYQnPq77rm0IzmPn07hJMtLRa4X"
        ).unwrap();
        let g = Integer::base64_decode("Ag==").unwrap();
        let gamma = Integer::base64_decode(
            "hwImEFXuMLcCmXcexszjkKQvXs3rq0FIYF6+nVjx7yo0DRG2ce9ivF59LsXgGjJcQ61vELuhzNvAK2m2wdti24zdkdB3Yn/ZQdVHh97xjP9cXDosTUumhye9wXhfHzqcKomS5njrlR8+Lzkc3PzUZRl877DmFflAw68yOZLJIZrqq0hf9zgdBNdYi9Tz1BaMMTqkQ3ZI4ZCkdO0XAmZ+mV4UJT4B4YLIBekSAR94UDHfe6hGvDib4LqU1BDC43xU3BdX2jC3e9gzysvqMjg5cUS0prUAY4lgYOhuzaa2P/P9RUicr/oYRhFdlsCMLutvRrYCdKF8CpZQ3fkYlOcQeW4dtMaLjzgPiL5/Dnxl1ews2zoWF5RaJemZT2XvebtrXO2yWDHwfelHcsUmgBzWgNYepEA/cbA/p7MmqWsLfHPCVUMf1Hhw/VFW/H3JJalXxSR1ulQugXwN3Yjnu73em3bHngZ4KDs1Pk+BkEZXnDJGeYDAlNu04A949d4y9r4n"
        ).unwrap();
        let phis: Vec<Integer> = [
            "i5b35oK7XPck5dxccqr2/YdbRi8djAqEWOirAP3BZ0D1IHcY7QBaPt1vRrr8aQmAk7hwhNhQRmZcXr8WJPlm/QzPBlxaWxd9oejQscZj2123hnw2/IR10X7zZM16J55QnQq6q0nJ/Y/w8du6zjbtES2cpUPEoCKpBS9wONsOpL/mlAGkKxRrqxFWNl/P90qm2HaCbHvuX7Y+bG6Q4y4+sp6ztInG/Y8R9PAxknVN65u2eYp8kJNGcUl5QPTF68TJFoOAu1cV7IfiJm3s7+d6spmGCXeyoZJCcHDcscC7h1xzQpHxf3x8NnX5Emq9BVzqsLJNw32OYLnnCec3n102VfauPneSQRmFok0ZaMix+pmJIodUuugdw49wZmdsmax2vvvbn85PGkc2QfYV9KFgfIRLugJI+3guiiS2xbOnldR//3RgnWHrVuCLPEtb6C6pm3gaWXKV8z6KB+ZqCl8tXOVRRRDK5OSfpsXksq0wk811WFbcFxFsY42rWd/X44Of"
        ]
            .iter()
            .map(|s| Integer::base64_decode(s).unwrap())
            .collect();
        let pks: Vec<Integer> = [
            "RRvARDZPWY04Itn3uIfnxpwpMen52V0oHuEFNCbOOIcku63jiz2nQ9YNnlaO5Oi332Go1xsJJrfUTEhhxvi57uuLqRbwzm6mv9o2CabIGxLZVO82KMnQqSv/ACDoFNtWWxBjQBGOjDeJgiJMfp7qW+M+O3urhbh4OMvUQhYC46LhiGMyTjn3hq0YWN2MdVHHbr8URaGVwBO56F6+FWQN8+wHJFbCd+ksqQsJqq9We4PZPAIVpuez4UPsK5TNl8ll2LaicHVFF9SEh6vvAZKxZqKHczvG6mcZ0xLwKKeQhCvV5otqjdH2A0dFkcakb/zdluhFitU9XGYUGO9A18CCH0Rslhcc5q/ll/jAq/59jtXsjPG8QbBX036MeTD/V3fwtzC5lKyEcOFvNb2qo/4Pq6gsVqj2Mvf2BbJiEeigApZWyU6z+KrH20EY2sMmds08F0CGO0u98f2bu9HKQuc4KVNVsjXLTiXbHbwBkFJwL3kM9d234Cu6BewsImTvBG5p",
            "NNGbZx1wv60uB+K961wkBD82r1ZBpJxuUOifQ0ELt3mdjlypJOFDFmxaas6qp0GV/h882lcFzq0VjwQdhLukJgpOgVXQaJpahGeHGO9oMFfD9+lAvF1wvKegSoiHkIad/CfvsQ+Q7hy9XdwVhw7s0yRCnlPISEcCG/RiRunZFtIvaVl/Mw+VFKWMyYiu31X5GQO58iTfArGbsXEUntCFNj4bMt8KsZixfFejT5I4Kb1S+Ef6Cs5XgZeUzmfGuFSy34rkqNLIGo8e1qSlBz9QxgNlH6g2s1Ys8sOt6XMA/rhLYd58WH8YJ1S/dgWd0mgCPsAE4sMpsNJ8Z90atybHz0E4rPwdu2pshFyZVHzQ2vFxTbAh9i2oM24gYBrexfnVvEjGpJm9/3l2yEdQSKK4tSDwfARROJzW4epcnZBSP7dGtNI2PbN2NdX+LaQ6Ro5nTAqYj6pcG6Wgeh4xvmF9aFVN69tC7ad3in5rMyRaxkPPCnfjcfXihT3vKugZJYpE"
        ]
            .iter()
            .map(|s| Integer::base64_decode(s).unwrap())
            .collect();
        let ms: Vec<Integer> = [
            "b1+42/kkpZlIkQBzHZB0V37PAoSNwfFyLFCeV8KCBKqe9bWGYRdkPCLNLL7ZG5p2YY5OleT509M3hHAXJQnxY5RY8ccI0wvMk8Bifr2zD0iogU35RbcUq8geI0hYN8r3m93ttjxnbg4G+/uqKeR6NEdmTmiSEnkvqoiyETUK7eONu5Vxpw7rGrxIezv4odUeKBeWLJcy7ICrvj2CQQANbAID1mVdgtRKik2PPm+UXbrlycg7Q3uDnTrjYJlm1hDC6dhlblKMozusNYO28acLRkqHlG1CqkHoT+GMifkJYw1GyolylePRkCCgXxK2pDWLoj+nIH9zTwztT2XDRfrYKVrBEjYwx1VMvS2HoxpHOOnhw7BTcsyapV9vMyYkySGaONEGDIGohmGIi4ZIU/w+NDry2r1bMpUOYM1CtR6J4i6RHHC+7yE9kWU7pWI/mlkj0HOWY3V255jnJ6INyiT8O5osIxfdsU/cL0pCUlnKEhWQndySJFSWoIw1vdFn5qFX"
        ]
            .iter()
            .map(|s| Integer::base64_decode(s).unwrap())
            .collect();
        let e = Integer::base64_decode("p3pQAidAXNZEqIy6TEp/pE6TFumQ1x7J52OeHJv89SA=").unwrap();
        let zs: Vec<Integer> = [
            "IZTHyehy21Yz9o3Ix+S/0vgIRN4hnx7Q+/5+NJfViW7grhaTmokMKuGwpe+/AwGBk+QXZJHSLGNwhht1kSAQNCAlHxYTGXkPjbGw4+QTdA+A3jMaJAeMfQLoCwPDaldNbyb/J+usnofX+j0SGUW3ObAMVcUVWh/JyPG/KVjilmf2sdAqji8qX0N3bkN/7Sb7YH0rhJa9zk0pe7EIlUVaVHYfRUqd8eIe31A5NQJ2wavwavCewHwYvANq5e3274x0Cd9AHQ1EPC3NQiVms+8xyKCtEZ516F7cwiyLIrXeTbuywmssUZq9ru6+ZfsgtOPGmRzDlBdblKNDGj/+0UnjbSGgrm99W+75zZZVZVpa6tPV6n1bbiTd8msQAuMFdYz3qQ7NPUqy3WpuwUH9KvkXU3KP/k7ZaG+VmLEbMbXrIhcrARwIYwLS8aCmzyB5kBuLxSXyEeKiQdhiz/fqUUZlv3CoUHOSdmvAyAcia7my8uDUW1x0gbS4ByWIFdjIr/ee"
        ]
            .iter()
            .map(|s| Integer::base64_decode(s).unwrap())
            .collect();
        let res = verify_decryption(
            &EncryptionParameters::from((&p, &q, &g)),
            &Ciphertext::from_expanded(&gamma, &phis),
            &pks,
            &ms,
            &[
                "71A1AB434A03A212E143869E580CA311".to_string(),
                "49E21ADEFC8BE89CED94F4104BFFB219".to_string(),
                "MixDecOnline".to_string(),
                "1".to_string(),
            ],
            (&e, &zs),
        );
        assert!(res.is_ok());
        assert!(res.unwrap())
    }
}
