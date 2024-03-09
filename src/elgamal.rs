//! Implementation of El Gamal functionalitiies and the structure for the Encryption parameters

use crate::{
    basic_crypto_functions::{shake256, BasisCryptoError},
    byte_array::ByteArray,
    integer::Constants,
    number_theory::{NumberTheoryError, NumberTheoryMethodTrait, SmallPrimeTrait, SMALL_PRIMES},
    HashableMessage, SECURITY_LENGTH,
};
use num_bigint::BigUint;
use thiserror::Error;

/// Encryption parameters for the ecryption system according to the specification of Swiss Post
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionParameters {
    p: BigUint,
    q: BigUint,
    g: BigUint,
}

impl EncryptionParameters {
    /// The parameter `p` according to the specification of Swiss Post
    pub fn p(&self) -> &BigUint {
        &self.p
    }

    /// The parameter `q` according to the specification of Swiss Post
    pub fn q(&self) -> &BigUint {
        &self.q
    }

    /// The parameter `g` according to the specification of Swiss Post
    pub fn g(&self) -> &BigUint {
        &self.g
    }

    /// Set the parameter `p`.
    ///
    /// This method should only be used in special cases, e.g. for moking
    pub fn set_p(&mut self, p: &BigUint) {
        self.p = p.clone();
    }

    /// Set the parameter `q`.
    ///
    /// This method should only be used in special cases, e.g. for moking
    pub fn set_q(&mut self, q: &BigUint) {
        self.q = q.clone();
    }

    /// Set the parameter `g`.
    ///
    /// This method should only be used in special cases, e.g. for moking
    pub fn set_g(&mut self, g: &BigUint) {
        self.g = g.clone();
    }

    // GetEncryptionParameters according to the specification of Swiss Post (Algorithm 8.1)
    pub fn get_encryption_parameters(seed: &str) -> Result<Self, ElgamalError> {
        let q_b_hat = shake256(&ByteArray::from(seed)).map_err(ElgamalError::OpenSSLError)?;
        let q_b = q_b_hat.prepend_byte(2u8);
        let q_prime: BigUint = q_b.into_biguint() >> 3;
        let q = &q_prime - (&q_prime % 6u8) + BigUint::five();
        let rs: Vec<BigUint> = SMALL_PRIMES.iter().map(|sp| &q % sp).collect();
        let mut delta = BigUint::zero().clone();
        let jump = BigUint::from(6u8);
        loop {
            loop {
                delta += &jump;
                let mut i: usize = 0;
                while i < rs.len() {
                    if (&rs[i] + &delta) % SMALL_PRIMES[i] == *BigUint::zero()
                        || ((&rs[i] + &delta) * BigUint::two() + BigUint::one()) % SMALL_PRIMES[i]
                            == *BigUint::zero()
                    {
                        delta += &jump;
                        i = 0;
                    } else {
                        i += 1;
                    }
                }
                if (&q + &delta).miller_rabin(1)
                    && ((&q + &delta) * BigUint::two() + BigUint::one()).miller_rabin(1)
                {
                    break;
                }
            }
            if (&q + &delta).miller_rabin(SECURITY_LENGTH / 2)
                && ((&q + &delta) * BigUint::two() + BigUint::one())
                    .miller_rabin(SECURITY_LENGTH / 2)
            {
                break;
            }
        }
        let q_final = &q + &delta;
        let p = &q_final * BigUint::two() + BigUint::one();
        let g: u8 = match BigUint::two().is_quadratic_residue(&p) {
            true => 2,
            false => 3,
        };
        Ok(EncryptionParameters {
            p,
            q: q_final,
            g: BigUint::from(g),
        })
    }

    /// Check the encryption parameters according to the domain definition in the specifications
    ///
    /// Return a [ElgamalError] if the check is not positive. Else None
    pub fn check_encryption_parameters(&self) -> Option<ElgamalError> {
        if let Some(e) = check_p(&self.p) {
            return Some(e);
        }
        if let Some(e) = check_q(&self.p, &self.q) {
            return Some(e);
        }
        if let Some(e) = check_g(&self.p, &self.g) {
            return Some(e);
        }
        None
    }

    /// Transform the parameters to a tuple
    pub fn as_tuple(&self) -> (&BigUint, &BigUint, &BigUint) {
        (&self.p, &self.q, &self.g)
    }
}

impl From<(&BigUint, &BigUint, &BigUint)> for EncryptionParameters {
    fn from(value: (&BigUint, &BigUint, &BigUint)) -> Self {
        EncryptionParameters {
            p: value.0.clone(),
            q: value.1.clone(),
            g: value.2.clone(),
        }
    }
}

impl<'a> From<&'a EncryptionParameters> for HashableMessage<'a> {
    fn from(value: &'a EncryptionParameters) -> Self {
        Self::from(vec![
            Self::from(value.p()),
            Self::from(value.q()),
            Self::from(value.g()),
        ])
    }
}

// Get small prime group members according to the specifications of Swiss Post (Algorithm 8.2)
pub fn get_small_prime_group_members(
    ep: &EncryptionParameters,
    desired_number: usize,
) -> Result<Vec<usize>, ElgamalError> {
    let mut current = 5usize;
    let mut res = vec![];
    while res.len() < desired_number
        && &BigUint::from(current) < ep.p()
        && current < usize::pow(2, 31)
    {
        let is_prime = current.is_small_prime().unwrap();
        if is_prime && BigUint::from(current).is_quadratic_residue(ep.p()) {
            res.push(current);
        }
        current += 2;
    }
    if res.len() != desired_number {
        return Err(ElgamalError::TooFewSmallPrimeNumbers {
            expected: desired_number,
            found: res.len(),
        });
    }
    Ok(res)
}

/// Check p as part of encryption parameter
///
/// Return a [ElgamalError] if the check is not positive. Else None
pub fn check_p(p: &BigUint) -> Option<ElgamalError> {
    p.check_prime().map(ElgamalError::CheckNumberTheory)
}

/// Check q as part of encryption parameter
///
/// Return a [ElgamalError] if the check is not positive. Else None
pub fn check_q(p: &BigUint, q: &BigUint) -> Option<ElgamalError> {
    if *p != q * 2u8 + 1u8 {
        return Some(ElgamalError::CheckRelationPQ);
    }
    q.check_prime().map(ElgamalError::CheckNumberTheory)
}

/// Check g as part of encryption parameter
///
/// Return a [ElgamalError] if the check is not positive. Else None
pub fn check_g(p: &BigUint, g: &BigUint) -> Option<ElgamalError> {
    if g == BigUint::one() {
        return Some(ElgamalError::CheckNotOne);
    }
    g.check_quadratic_residue(p)
        .map(ElgamalError::CheckNumberTheory)
}

// Enum reprsenting the elgamal errors
#[derive(Error, Debug)]
pub enum ElgamalError {
    #[error(transparent)]
    OpenSSLError(#[from] BasisCryptoError),
    #[error("To few number of small primes found. Expcted: {expected}, found: {found}")]
    TooFewSmallPrimeNumbers { expected: usize, found: usize },
    #[error("Number {0} with value {1} is not prime")]
    NotPrime(String, BigUint),
    #[error("The relation p=2q+1 is not satisfied")]
    CheckRelationPQ,
    #[error("The value should not be one")]
    CheckNotOne,
    #[error(transparent)]
    CheckNumberTheory(#[from] NumberTheoryError),
}

#[cfg(test)]
mod test {
    use super::super::integer::Hexa;
    use super::*;

    #[test]
    fn test_get_small_prime_group_members() {
        let ep = EncryptionParameters::from((
            &BigUint::from_hexa_string(
                "0xCE9E0307D2AE75BDBEEC3E0A6E71A279417B56C955C602FFFD067586BACFDAC3BCC49A49EB4D126F5E9255E57C14F3E09492B6496EC8AC1366FC4BB7F678573FA2767E6547FA727FC0E631AA6F155195C035AF7273F31DFAE1166D1805C8522E95F9AF9CE33239BF3B68111141C20026673A6C8B9AD5FA8372ED716799FE05C0BB6EAF9FCA1590BD9644DBEFAA77BA01FD1C0D4F2D53BAAE965B1786EC55961A8E2D3E4FE8505914A408D50E6B99B71CDA78D8F9AF1A662512F8C4C3A9E72AC72D40AE5D4A0E6571135CBBAAE08C7A2AA0892F664549FA7EEC81BA912743F3E584AC2B2092243C4A17EC98DF079D8EECB8B885E6BBAFA452AAFA8CB8C08024EFF28DE4AF4AC710DCD3D66FD88212101BCB412BCA775F94A2DCE18B1A6452D4CF818B6D099D4505E0040C57AE1F3E84F2F8E07A69C0024C05ACE05666A6B63B0695904478487E78CD0704C14461F24636D7A3F267A654EEDCF8789C7F627C72B4CBD54EED6531C0E54E325D6F09CB648AE9185A7BDA6553E40B125C78E5EAA867"
            ).unwrap(),
            &BigUint::from_hexa_string(
                "0x5FFB3E665707B0D9C5D3856B9B67D4751425AEB6575F97F697E446856FFCF159105FECE66D2CDE9DEA958966FE67A0D51ECDFC0FCAD3EACA293485FA2FBCC9DF3B055DE51F14B82EA39D3331C6E6B753C331E06DC8F1F0558EFF0D7F928C0EA6961DD02CFC898ECAE9BFA18919F5113B702964B06E58987CEFFEE05F4BBE4CA3F3D702F528B5540D92947F781B12D67E7A4AE1D5AEAF8BB703789C1574B52381908496060E0150CB55A6D1069B02DA73952E7E8B67C9C0E41A89F5E8C5452510DFCADC3276D26010A2C1F4CD18C07BD2B0F8CEA28DE21AA73D1426E3F5862D02EE2C42B636E4679D2BDA16C336C2FA29E8DEC663088BFDB035205785077BB6B01E3D183E05C42A1AAEAC1B3BA635D8911C704C033C15243DDCC44570EDAA6F651FF61BA698664D391698292C2834E9095B17EB3AC38819BE50BA08F417FBF3F3DBAA7A64F9D0E24D50AF0685074D82D17544010B68295BC07340B46519B184E9E0C01513C57E78E07C7D19C0E0A2ED0432449110DCB0766B6A30B2F02BDAAF75"
            ).unwrap(),
            &BigUint::from(3u8),
        ));
        assert_eq!(
            get_small_prime_group_members(&ep, 5).unwrap(),
            vec![5, 17, 19, 37, 41]
        );
    }

    #[test]
    #[ignore]
    fn test_get_encryption_parameters() {
        let ep_res = EncryptionParameters::get_encryption_parameters("31");
        assert!(ep_res.is_ok());
        let ep = ep_res.unwrap();
        let p_exp = BigUint::from_hexa_string(
            "0xBEDCDE3405B8A18D6C7615FCFF97DB1C29CD2CA69F1BB1432E690E1E947836FC1DE9160D5C2ADEE52ED244F7997ECCE19FF979D00CC3CCE3784DA6C6495D0D87337B24ABB0FD848C79EBBCF298349396FAE4031A3B7EC2BF313CAEF36AB191CAD36D4AEFDFFA87F72DAACB2EA854FFFCCC66E99C2896911EBA93341C006DD3AA4DD06B432B2D3FCD79B5F7C61DED181B734B2DC1C869E498B2647E8C4301DBFD1787F1C7F5E687D118F2A5D410DB73689586377AA9273DEEC051B60DB813DD0C22FAD561BABE3C59CC67EB284387EE6D3F8C38F6A0B34DE82CEF929B853C3B1A52C6CD6B87AA0A882C30F8B716B3687CCB8EB9EC1BF67407C5142315D2BDFFA5D37E0ADB968593BC66A999695DF11B0164B21A62F7A0A7006D49EF8DEB31408E66AD53A4A6BE38F20EF09C84C729A9544EDF854274DC2120CAFA1BC08E20E7C7F1969DCD4C2C08DCB8AB419B6A8B22F1D6F183B1912E54B045C84E95E668D282073EF9216E3106C173FF9A1D29DC445059491209FA9540D06B666611EB5ECE77"
        ).unwrap();
        let q_exp = BigUint::from_hexa_string(
            "0x5F6E6F1A02DC50C6B63B0AFE7FCBED8E14E696534F8DD8A19734870F4A3C1B7E0EF48B06AE156F729769227BCCBF6670CFFCBCE80661E671BC26D36324AE86C399BD9255D87EC2463CF5DE794C1A49CB7D72018D1DBF615F989E5779B558C8E569B6A577EFFD43FB96D56597542A7FFE663374CE144B488F5D499A0E0036E9D526E835A195969FE6BCDAFBE30EF68C0DB9A596E0E434F24C59323F462180EDFE8BC3F8E3FAF343E88C7952EA086DB9B44AC31BBD54939EF76028DB06DC09EE86117D6AB0DD5F1E2CE633F59421C3F7369FC61C7B5059A6F41677C94DC29E1D8D296366B5C3D5054416187C5B8B59B43E65C75CF60DFB3A03E28A118AE95EFFD2E9BF056DCB42C9DE3354CCB4AEF88D80B2590D317BD0538036A4F7C6F598A0473356A9D2535F1C7907784E426394D4AA276FC2A13A6E1090657D0DE0471073E3F8CB4EE6A616046E5C55A0CDB5459178EB78C1D8C8972A5822E4274AF3346941039F7C90B7188360B9FFCD0E94EE22282CA48904FD4AA06835B33308F5AF673B"
        ).unwrap();
        let g_exp = BigUint::from(2u8);
        assert_eq!(ep.p, p_exp);
        assert_eq!(ep.q, q_exp);
        assert_eq!(ep.g, g_exp);
    }

    #[test]
    fn test_check_p() {
        let p = BigUint::from_hexa_string(
            "0xCE9E0307D2AE75BDBEEC3E0A6E71A279417B56C955C602FFFD067586BACFDAC3BCC49A49EB4D126F5E9255E57C14F3E09492B6496EC8AC1366FC4BB7F678573FA2767E6547FA727FC0E631AA6F155195C035AF7273F31DFAE1166D1805C8522E95F9AF9CE33239BF3B68111141C20026673A6C8B9AD5FA8372ED716799FE05C0BB6EAF9FCA1590BD9644DBEFAA77BA01FD1C0D4F2D53BAAE965B1786EC55961A8E2D3E4FE8505914A408D50E6B99B71CDA78D8F9AF1A662512F8C4C3A9E72AC72D40AE5D4A0E6571135CBBAAE08C7A2AA0892F664549FA7EEC81BA912743F3E584AC2B2092243C4A17EC98DF079D8EECB8B885E6BBAFA452AAFA8CB8C08024EFF28DE4AF4AC710DCD3D66FD88212101BCB412BCA775F94A2DCE18B1A6452D4CF818B6D099D4505E0040C57AE1F3E84F2F8E07A69C0024C05ACE05666A6B63B0695904478487E78CD0704C14461F24636D7A3F267A654EEDCF8789C7F627C72B4CBD54EED6531C0E54E325D6F09CB648AE9185A7BDA6553E40B125C78E5EAA867"
        ).unwrap();
        assert!(check_p(&p).is_none());
        let p = BigUint::from(6u8);
        assert!(check_p(&p).is_some())
    }

    #[test]
    fn test_check_q() {
        let p = BigUint::from_hexa_string(
            "0xBFF67CCCAE0F61B38BA70AD736CFA8EA284B5D6CAEBF2FED2FC88D0ADFF9E2B220BFD9CCDA59BD3BD52B12CDFCCF41AA3D9BF81F95A7D59452690BF45F7993BE760ABBCA3E29705D473A66638DCD6EA78663C0DB91E3E0AB1DFE1AFF25181D4D2C3BA059F9131D95D37F431233EA2276E052C960DCB130F9DFFDC0BE977C9947E7AE05EA516AA81B2528FEF03625ACFCF495C3AB5D5F176E06F1382AE96A470321092C0C1C02A196AB4DA20D3605B4E72A5CFD16CF9381C83513EBD18A8A4A21BF95B864EDA4C0214583E99A3180F7A561F19D451BC4354E7A284DC7EB0C5A05DC58856C6DC8CF3A57B42D866D85F453D1BD8CC61117FB606A40AF0A0EF76D603C7A307C0B8854355D5836774C6BB12238E09806782A487BB9888AE1DB54DECA3FEC374D30CC9A722D3052585069D212B62FD6758710337CA17411E82FF7E7E7B754F4C9F3A1C49AA15E0D0A0E9B05A2EA880216D052B780E68168CA336309D3C1802A278AFCF1C0F8FA3381C145DA0864892221B960ECD6D46165E057B55EEB"
        ).unwrap();
        let q = BigUint::from_hexa_string(
            "0x5FFB3E665707B0D9C5D3856B9B67D4751425AEB6575F97F697E446856FFCF159105FECE66D2CDE9DEA958966FE67A0D51ECDFC0FCAD3EACA293485FA2FBCC9DF3B055DE51F14B82EA39D3331C6E6B753C331E06DC8F1F0558EFF0D7F928C0EA6961DD02CFC898ECAE9BFA18919F5113B702964B06E58987CEFFEE05F4BBE4CA3F3D702F528B5540D92947F781B12D67E7A4AE1D5AEAF8BB703789C1574B52381908496060E0150CB55A6D1069B02DA73952E7E8B67C9C0E41A89F5E8C5452510DFCADC3276D26010A2C1F4CD18C07BD2B0F8CEA28DE21AA73D1426E3F5862D02EE2C42B636E4679D2BDA16C336C2FA29E8DEC663088BFDB035205785077BB6B01E3D183E05C42A1AAEAC1B3BA635D8911C704C033C15243DDCC44570EDAA6F651FF61BA698664D391698292C2834E9095B17EB3AC38819BE50BA08F417FBF3F3DBAA7A64F9D0E24D50AF0685074D82D17544010B68295BC07340B46519B184E9E0C01513C57E78E07C7D19C0E0A2ED0432449110DCB0766B6A30B2F02BDAAF75"
        ).unwrap();
        assert!(check_q(&p, &q).is_none());
        let p1 = BigUint::from(13u8);
        let q1 = BigUint::from(6u8);
        let p2 = BigUint::from(11u8);
        let q2 = BigUint::from(7u8);
        assert!(check_q(&p1, &q1).is_some());
        assert!(check_q(&p2, &q2).is_some());
    }

    #[test]
    fn test_check_g() {
        let p = BigUint::from(11u8);
        let g_ok = BigUint::from(3u8);
        let g_err = BigUint::from(2u8);
        assert!(check_g(&p, &g_ok).is_none());
        assert!(check_g(&p, &g_err).is_some());
        assert!(check_g(&p, BigUint::one()).is_some())
    }

    #[test]
    fn test_check_encryption_parameters() {
        let p = BigUint::from_hexa_string(
            "0xBFF67CCCAE0F61B38BA70AD736CFA8EA284B5D6CAEBF2FED2FC88D0ADFF9E2B220BFD9CCDA59BD3BD52B12CDFCCF41AA3D9BF81F95A7D59452690BF45F7993BE760ABBCA3E29705D473A66638DCD6EA78663C0DB91E3E0AB1DFE1AFF25181D4D2C3BA059F9131D95D37F431233EA2276E052C960DCB130F9DFFDC0BE977C9947E7AE05EA516AA81B2528FEF03625ACFCF495C3AB5D5F176E06F1382AE96A470321092C0C1C02A196AB4DA20D3605B4E72A5CFD16CF9381C83513EBD18A8A4A21BF95B864EDA4C0214583E99A3180F7A561F19D451BC4354E7A284DC7EB0C5A05DC58856C6DC8CF3A57B42D866D85F453D1BD8CC61117FB606A40AF0A0EF76D603C7A307C0B8854355D5836774C6BB12238E09806782A487BB9888AE1DB54DECA3FEC374D30CC9A722D3052585069D212B62FD6758710337CA17411E82FF7E7E7B754F4C9F3A1C49AA15E0D0A0E9B05A2EA880216D052B780E68168CA336309D3C1802A278AFCF1C0F8FA3381C145DA0864892221B960ECD6D46165E057B55EEB"
        ).unwrap();
        let q = BigUint::from_hexa_string(
            "0x5FFB3E665707B0D9C5D3856B9B67D4751425AEB6575F97F697E446856FFCF159105FECE66D2CDE9DEA958966FE67A0D51ECDFC0FCAD3EACA293485FA2FBCC9DF3B055DE51F14B82EA39D3331C6E6B753C331E06DC8F1F0558EFF0D7F928C0EA6961DD02CFC898ECAE9BFA18919F5113B702964B06E58987CEFFEE05F4BBE4CA3F3D702F528B5540D92947F781B12D67E7A4AE1D5AEAF8BB703789C1574B52381908496060E0150CB55A6D1069B02DA73952E7E8B67C9C0E41A89F5E8C5452510DFCADC3276D26010A2C1F4CD18C07BD2B0F8CEA28DE21AA73D1426E3F5862D02EE2C42B636E4679D2BDA16C336C2FA29E8DEC663088BFDB035205785077BB6B01E3D183E05C42A1AAEAC1B3BA635D8911C704C033C15243DDCC44570EDAA6F651FF61BA698664D391698292C2834E9095B17EB3AC38819BE50BA08F417FBF3F3DBAA7A64F9D0E24D50AF0685074D82D17544010B68295BC07340B46519B184E9E0C01513C57E78E07C7D19C0E0A2ED0432449110DCB0766B6A30B2F02BDAAF75"
        ).unwrap();
        let g = BigUint::from(3u8);
        let p_err = BigUint::from(11u8);
        let q_err_1 = BigUint::from(6u8);
        let q_err_2 = BigUint::from(11u8);
        let g_err = BigUint::from(2u8);
        assert!(EncryptionParameters::from((&p, &q, &g))
            .check_encryption_parameters()
            .is_none());
        assert!(EncryptionParameters::from((&p_err, &q, &g))
            .check_encryption_parameters()
            .is_some());
        assert!(EncryptionParameters::from((&p, &q_err_1, &g))
            .check_encryption_parameters()
            .is_some());
        assert!(EncryptionParameters::from((&p, &q_err_2, &g))
            .check_encryption_parameters()
            .is_some());
        assert!(EncryptionParameters::from((&p, &q, &g_err))
            .check_encryption_parameters()
            .is_some());
        assert!(EncryptionParameters::from((&p, &q, BigUint::one()))
            .check_encryption_parameters()
            .is_some());
    }
}
