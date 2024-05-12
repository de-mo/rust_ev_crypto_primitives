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

//! Impement necessary Hash algorithms for the crate

use super::BasisCryptoError;
use crate::byte_array::ByteArray;
use openssl::{
    hash::{hash_xof, MessageDigest},
    md::Md,
    md_ctx::MdCtx,
};

/// Wrapper for SHA3-256
///
/// # Error
/// [OpensslError] if something is going wrong
pub fn sha3_256(byte_array: &ByteArray) -> Result<ByteArray, BasisCryptoError> {
    let mut ctx = MdCtx::new().map_err(|e| BasisCryptoError::HashError {
        msg: "Error creating MdCtx".to_string(),
        source: e,
    })?;
    ctx.digest_init(Md::sha3_256())
        .map_err(|e| BasisCryptoError::HashError {
            msg: "Error digest_init".to_string(),
            source: e,
        })?;
    ctx.digest_update(&byte_array.to_bytes())
        .map_err(|e| BasisCryptoError::HashError {
            msg: "Error digest_update".to_string(),
            source: e,
        })?;
    let mut digest = [0; 32];
    ctx.digest_final(&mut digest)
        .map_err(|e| BasisCryptoError::HashError {
            msg: "Error digest_final".to_string(),
            source: e,
        })?;
    Ok(ByteArray::from_bytes(&digest))
}

/// Wrapper for SHA256
///
/// # Error
/// [OpensslError] if something is going wrong
#[allow(dead_code)]
pub fn sha256(byte_array: &ByteArray) -> Result<ByteArray, BasisCryptoError> {
    let mut ctx = MdCtx::new().map_err(|e| BasisCryptoError::HashError {
        msg: "Error creating MdCtx".to_string(),
        source: e,
    })?;
    ctx.digest_init(Md::sha256())
        .map_err(|e| BasisCryptoError::HashError {
            msg: "Error digest_init".to_string(),
            source: e,
        })?;
    ctx.digest_update(&byte_array.to_bytes())
        .map_err(|e| BasisCryptoError::HashError {
            msg: "Error digest_update".to_string(),
            source: e,
        })?;
    let mut digest = [0; 32];
    ctx.digest_final(&mut digest)
        .map_err(|e| BasisCryptoError::HashError {
            msg: "Error digest_final".to_string(),
            source: e,
        })?;
    Ok(ByteArray::from_bytes(&digest))
}

/// Wrapper for SHAKE128
///
/// # Error
/// [OpensslError] if something is going wrong
#[allow(dead_code)]
pub fn shake128(byte_array: &ByteArray, length: usize) -> Result<ByteArray, BasisCryptoError> {
    let mut digest = vec![0; length];
    hash_xof(
        MessageDigest::shake_128(),
        &byte_array.to_bytes(),
        digest.as_mut_slice(),
    )
    .map_err(|e| BasisCryptoError::HashError {
        msg: "Error hash_xof".to_string(),
        source: e,
    })?;
    Ok(ByteArray::from_bytes(&digest))
}

/// Wrapper for SHAKE256
///
/// # Error
/// [OpensslError] if something is going wrong
pub fn shake256(byte_array: &ByteArray, length: usize) -> Result<ByteArray, BasisCryptoError> {
    let mut digest = vec![0; length];
    hash_xof(
        MessageDigest::shake_256(),
        &byte_array.to_bytes(),
        digest.as_mut_slice(),
    )
    .map_err(|e| BasisCryptoError::HashError {
        msg: "Error hash_xof".to_string(),
        source: e,
    })?;
    Ok(ByteArray::from_bytes(&digest))
}

#[cfg(test)]
mod test {
    use super::super::super::byte_array::Decode;
    use super::*;
    use crate::GROUP_PARAMETER_P_LENGTH;

    #[test]
    fn test_sha3_256() {
        let e: Vec<u8> = vec![
            28u8, 158u8, 189u8, 108u8, 175u8, 2u8, 132u8, 10u8, 91u8, 43u8, 127u8, 15u8, 200u8,
            112u8, 236u8, 29u8, 177u8, 84u8, 136u8, 106u8, 233u8, 254u8, 98u8, 27u8, 130u8, 43u8,
            20u8, 253u8, 11u8, 245u8, 19u8, 214u8,
        ];
        assert_eq!(
            sha3_256(&ByteArray::from_bytes(b"\x41"))
                .unwrap()
                .to_bytes(),
            e
        );
    }

    #[test]
    fn test_sha256() {
        assert_eq!(
            sha256(&ByteArray::from_bytes(b"Some Crypto Text"))
                .unwrap()
                .to_bytes(),
            b"\x60\x78\x56\x38\x8a\xca\x5c\x51\x83\xc4\xd1\x4d\xc8\xf9\xcc\xf2\
            \xa5\x21\xb3\x10\x93\x72\xfa\xd6\x7c\x55\xf5\xc9\xe3\xd1\x83\x19"
        );
    }

    #[test]
    fn test_shake128() {
        assert_eq!(
            shake128(&ByteArray::from_bytes(b"Some Crypto Text"), GROUP_PARAMETER_P_LENGTH / 8).unwrap(),
            ByteArray::base16_decode(
                "76237D07F362A5A115FFA4830C75DD2AAEC818FB7236A35FF1643300FBA19D3EDF90490E8B05B26926E8A5FF2F2A4E16526CFA48B11B4A0FDBD8AA1AA124F578671ACEC8B51D154F1DFDE424D51EC26A8F8DFD2253550F3421E18E967509D1C26FCAB13410093C7EAF57B4C2CFD9505E99714BCA3D558B1E9DF23DEE0623854378E1B1077904D77192482DA475210EB023432FF9154D6F655020DE494AD8B3732BA89606C1E54E8260F49C4E6DB7B4408568192F72E08883C016681D9869F622393D824EE579BD70BF1C8B50ED90A1B6091A5E6A0E9C6DCBC57C6005BCED5F9E01FCEA3B4D96FE24475FF73A85A451DE673875D262D76CCFE583503F509EF957B25B2CD5FACA49D1C813AF6854FDC7B1A27A6645964975B37B6DF4D2441F8832361F2DADD48FE8C47D57D4F33AF1C85977ABE2A58D8CEB4366BD46801DC14837005A6496D4BDE2A154EA99BE6F4453501CF827E5108D067C8BFBDF8FB7BDC1D221DB11B34BD47AFC88B4D1DBEA7E967111631E22E40AF45735E1E789DBB7178F"
            )
            .unwrap()
        );
    }

    #[test]
    fn test_shake256() {
        assert_eq!(
            shake256(&ByteArray::from_bytes(b"Some Crypto Text"), GROUP_PARAMETER_P_LENGTH / 8).unwrap(),
            ByteArray::base16_decode(
                "36D790E2881A710CE583CD643E9AAFF6FCEF86BAD49B849656C7060871AA8A837A9191B0BDE0F7EE3B57787BF5CAF0B4387C7ACAD063F409CB1CD4E4B2E0163E35DCCDCE60141B486395C672C7DE808D4B98EA84083F655F76CD23C5CDC6CA9FB1F5099FF3F2BB0753B7EBB8C0D576F5299402AE752D420BB8B8CF6B24094008349C7992FDCCB81DFA3292AB9167D7EB9E79440EA82AE25521746F2720B794E6B528CDFA1437CA289AD0753570B4BD38159F50FD1ACE554C97D065EB055D08FF85F330240B7B21D62C315C995E34D42D7570D4F01D4FF93F7DC665664130A6F001E36F47374B1C40ABE7010C4B14BEEB1FEAF41BFEEC0DCE87FFAEA758C53F7F7C0BCB590621AF4A393845BDBA734296D920B8F71D02A7A4CA2666EC7890034C2DF7D0F64D27E1A3E281058DE11F2859A270988EC60C56BD8AF81ED290ADF8F4B02B3C4FF095AFAAEC4BC8B942845CE9566A4B9C564E11A0888FF56DBC254CD6E86DE958A6346D1A8DD6025165A64E4F8596C2562CB7071078A47DC2DA9285F0"
            )
            .unwrap()
        );
    }
}
