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

//! Implementation of recursive hash functionality
//!

use crate::{
    basic_crypto_functions::{sha3_256, shake256, BasisCryptoError},
    byte_array::{ByteArray, ByteArrayError},
    integer::MPInteger,
    GROUP_PARAMETER_Q_LENGTH, SECURITY_STRENGTH,
};
use chrono::NaiveDateTime;
use std::fmt::Debug;
use thiserror::Error;

/// Trait implementing defining an interface for objects implementing a recursive hash function.
///
/// The enum [HashableMessage] implements the trait.
pub trait RecursiveHashTrait {
    /// Try recursive hash
    ///
    /// Return [HashError] if an error appears during the calculation
    fn try_recursive_hash(&self) -> Result<ByteArray, HashError>;

    /// Recursive hash
    ///
    /// Panic if an error appears during the calculation
    fn recursive_hash(&self) -> ByteArray {
        self.try_recursive_hash().unwrap()
    }

    /// Try recursive hash and return a variant HashableMessage::Hashed containing the hashed value
    ///
    /// Return [HashError] if an error appears during the calculation
    fn try_to_hashed_hashable_message(&self) -> Result<HashableMessage<'_>, HashError> {
        Ok(HashableMessage::Hashed(self.try_recursive_hash()?))
    }

    /// Recursive hash and return a variant HashableMessage::Hashed containing the hashed value
    ///
    /// Panic if an error appears during the calculation
    fn to_hashed_hashable_message(&self) -> HashableMessage<'_> {
        self.try_to_hashed_hashable_message().unwrap()
    }

    /// Try recursive hash of length: Computes the hash value of multiple inputs to a given bit length
    ///
    /// Return [HashError] if an error appears during the calculation
    fn try_recursive_hash_of_length(&self, length: usize) -> Result<ByteArray, HashError>;

    /// Recursive hash
    ///
    /// Panic if an error appears during the calculation
    fn recursive_hash_of_length(&self, length: usize) -> ByteArray {
        self.try_recursive_hash_of_length(length).unwrap()
    }

    /// Try recursive hash to Zq: Computes the hash value of multiple inputs uniformly into Z_q
    ///
    /// Return [HashError] if an error appears during the calculation
    fn try_recursive_hash_to_zq(&self, q: &MPInteger) -> Result<MPInteger, HashError>;

    /// Recursive hash
    ///
    /// Panic if an error appears during the calculation
    fn recursive_hash_to_zq(&self, q: &MPInteger) -> MPInteger {
        self.try_recursive_hash_to_zq(q).unwrap()
    }
}

/// Enum to represent an element that is hashable
///
/// The specifiction of Swiss Post give the list of possible
/// elements that can be hashable.
///
/// To avoid copy of existing elements (and big memory growth), the HashableMessage
/// contains possibly references to data. HashableMessage has the lifetime of the reference.
///
/// For simplification for the consumer, the enum contains the possibility to reference String or &str and the possibility
/// to reference to MPInteger or usize
///
/// Since [HashableMessage] implements the trait [RecursiveHashTrait], the trait must be used in a client module
/// in order to hash the message.
///
/// Example:
/// ```
/// use rust_ev_crypto_primitives::ByteArray;
/// use rust_ev_crypto_primitives::Decode;
/// use rust_ev_crypto_primitives::{HashableMessage, RecursiveHashTrait};
/// let r = HashableMessage::from("test string").hash();
/// let expected = ByteArray::base64_decode("m1a11iWW/Tcihy/IChyY51AO8UdZe48f5oRFh7RL+JQ=").unwrap();
/// assert_eq!(r, expected);
/// ```
///
/// In the specification of SwissPost, lists with various types of elements are hashed recursivly. Since Rust doesn't allow simple
/// the use of lists with different elements, the elemets must be first transformed in [HashableMessage] and then put in a [vec].
/// ```
/// use rust_ev_crypto_primitives::{HashableMessage, RecursiveHashTrait};
/// let mut l: Vec<HashableMessage> = vec![];
/// l.push(HashableMessage::from("common reference string"));
/// l.push(HashableMessage::from(&(2 as usize)));
/// HashableMessage::from(l).hash();
/// ```
///
/// If you decide to calculate intermediate hash values, and store the in the message (to avoid big structures),
/// use the variant [HashableMessage::Hashed]
/// ```
/// use rust_ev_crypto_primitives::{HashableMessage, RecursiveHashTrait};
/// let b = HashableMessage::from(2 as usize).hash();
/// let hm = HashableMessage::Hashed(b.clone());
/// assert_eq!(hm.hash(), b);
/// ```

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashableMessage<'a> {
    RByteArray(&'a ByteArray),
    ByteArray(ByteArray),
    RInt(&'a MPInteger),
    Int(MPInteger),
    RUSize(&'a usize),
    USize(usize),
    RString(&'a String),
    RStr(&'a str),
    String(String),
    Composite(Vec<HashableMessage<'a>>),
    CompositeR(Vec<&'a HashableMessage<'a>>),
    Hashed(ByteArray),
    HashedOfLength(ByteArray),
}

// Enum representing the error generated by the module [hahsing]
#[derive(Error, Debug)]
pub enum HashError {
    #[error(transparent)]
    HashError(#[from] BasisCryptoError),
    #[error(transparent)]
    ByteArrayError(#[from] ByteArrayError),
    #[error("The value is hashed with {0}, which is wrong")]
    WrongHashed(String),
}

impl<'a> HashableMessage<'a> {
    /// Hashable to byte_array accordind the specification of Swiss Post (Algorithm 5.5)
    fn to_hashable_byte_array(&self) -> Result<ByteArray, HashError> {
        match self {
            HashableMessage::RByteArray(b) => Ok(b.prepend_byte(0u8)),
            HashableMessage::ByteArray(b) => Ok(b.prepend_byte(0u8)),
            HashableMessage::RInt(i) => Ok(ByteArray::from(*i).prepend_byte(1u8)),
            HashableMessage::Int(i) => Ok(ByteArray::from(i).prepend_byte(1u8)),
            HashableMessage::RUSize(i) => Ok(ByteArray::from(*i).prepend_byte(1u8)),
            HashableMessage::USize(i) => Ok(ByteArray::from(i).prepend_byte(1u8)),
            HashableMessage::RString(s) => Ok(ByteArray::from(s.as_str()).prepend_byte(2u8)),
            HashableMessage::String(s) => Ok(ByteArray::from(s.as_str()).prepend_byte(2u8)),
            HashableMessage::RStr(s) => Ok(ByteArray::from(*s).prepend_byte(2u8)),
            HashableMessage::Composite(c) => {
                let mut res = ByteArray::from_bytes(b"\x03");
                for e in c.iter() {
                    res = res.append(&e.try_recursive_hash()?);
                }
                Ok(res)
            }
            HashableMessage::CompositeR(c) => {
                let mut res = ByteArray::from_bytes(b"\x03");
                for e in c.iter() {
                    res = res.append(&e.try_recursive_hash()?);
                }
                Ok(res)
            }
            HashableMessage::Hashed(b) => Ok(b.clone()),
            HashableMessage::HashedOfLength(_) => {
                Err(HashError::WrongHashed("RecursiveHashOfLength".to_string()))
            }
        }
    }

    /// Hashable to byte_array for "OfLength" accordind the specification of Swiss Post (Algorithm 5.7)
    fn to_hashable_byte_array_of_length(&self, length: usize) -> Result<ByteArray, HashError> {
        match self {
            HashableMessage::RByteArray(b) => Ok(b.prepend_byte(0u8)),
            HashableMessage::ByteArray(b) => Ok(b.prepend_byte(0u8)),
            HashableMessage::RInt(i) => Ok(ByteArray::from(*i).prepend_byte(1u8)),
            HashableMessage::Int(i) => Ok(ByteArray::from(i).prepend_byte(1u8)),
            HashableMessage::RUSize(i) => Ok(ByteArray::from(*i).prepend_byte(1u8)),
            HashableMessage::USize(i) => Ok(ByteArray::from(i).prepend_byte(1u8)),
            HashableMessage::RString(s) => Ok(ByteArray::from(s.as_str()).prepend_byte(2u8)),
            HashableMessage::String(s) => Ok(ByteArray::from(s.as_str()).prepend_byte(2u8)),
            HashableMessage::RStr(s) => Ok(ByteArray::from(*s).prepend_byte(2u8)),
            HashableMessage::Composite(c) => {
                let mut res = ByteArray::from_bytes(b"\x03");
                for e in c.iter() {
                    res = res.append(&e.try_recursive_hash_of_length(length)?);
                }
                Ok(res)
            }
            HashableMessage::CompositeR(c) => {
                let mut res = ByteArray::from_bytes(b"\x03");
                for e in c.iter() {
                    res = res.append(&e.try_recursive_hash_of_length(length)?);
                }
                Ok(res)
            }
            HashableMessage::Hashed(_) => Err(HashError::WrongHashed("RecursiveHash".to_string())),
            HashableMessage::HashedOfLength(b) => Ok(b.clone()),
        }
    }

    pub fn is_hashed(&self) -> bool {
        matches!(self, HashableMessage::Hashed(_))
    }
}

impl<'a> RecursiveHashTrait for HashableMessage<'a> {
    fn try_recursive_hash(&self) -> Result<ByteArray, HashError> {
        let b = self.to_hashable_byte_array()?;
        Ok(match self.is_hashed() {
            true => b,
            false => sha3_256(&b).map_err(HashError::HashError)?,
        })
    }

    fn try_recursive_hash_of_length(&self, length: usize) -> Result<ByteArray, HashError> {
        let mut upper_l = length / 8;
        if length % 8 > 0 {
            upper_l += 1;
        }
        let b = self.to_hashable_byte_array_of_length(length)?;
        Ok(match self.is_hashed() {
            true => b,
            false => shake256(&b, upper_l)
                .map_err(HashError::HashError)?
                .cut_bit_length(length)
                .map_err(HashError::ByteArrayError)?,
        })
    }

    fn try_recursive_hash_to_zq(&self, q: &MPInteger) -> Result<MPInteger, HashError> {
        let hashable_q = HashableMessage::from(q);
        let hashable_message = HashableMessage::from("RecursiveHash");
        let mut parameters = vec![&hashable_q, &hashable_message];
        match self {
            HashableMessage::Composite(v) => {
                for e in v.iter() {
                    parameters.push(e);
                }
            }
            HashableMessage::CompositeR(v) => {
                for e in v.iter() {
                    parameters.push(e);
                }
            }
            _ => parameters.push(self),
        }
        let h_prime = HashableMessage::from(parameters)
            .try_recursive_hash_of_length(GROUP_PARAMETER_Q_LENGTH + 2 * SECURITY_STRENGTH)?
            .into_mp_integer();
        Ok(h_prime.modulo(q))
    }
}

impl<'a> From<&'a ByteArray> for HashableMessage<'a> {
    fn from(value: &'a ByteArray) -> Self {
        HashableMessage::RByteArray(value)
    }
}

impl<'a> From<ByteArray> for HashableMessage<'a> {
    fn from(value: ByteArray) -> Self {
        HashableMessage::ByteArray(value)
    }
}

impl<'a> From<&'a MPInteger> for HashableMessage<'a> {
    fn from(value: &'a MPInteger) -> Self {
        HashableMessage::RInt(value)
    }
}

impl<'a> From<MPInteger> for HashableMessage<'a> {
    fn from(value: MPInteger) -> Self {
        HashableMessage::Int(value)
    }
}

impl<'a> From<&'a usize> for HashableMessage<'a> {
    fn from(value: &'a usize) -> Self {
        HashableMessage::RUSize(value)
    }
}

impl<'a> From<usize> for HashableMessage<'a> {
    fn from(value: usize) -> Self {
        HashableMessage::USize(value)
    }
}

impl<'a> From<&'a String> for HashableMessage<'a> {
    fn from(value: &'a String) -> Self {
        HashableMessage::RString(value)
    }
}

impl<'a> From<String> for HashableMessage<'a> {
    fn from(value: String) -> Self {
        HashableMessage::String(value)
    }
}

impl<'a> From<&'a str> for HashableMessage<'a> {
    fn from(value: &'a str) -> Self {
        HashableMessage::RStr(value)
    }
}

impl<'a> From<&'a NaiveDateTime> for HashableMessage<'a> {
    fn from(value: &'a NaiveDateTime) -> Self {
        let s = value.format("%Y-%m-%dT%H:%M").to_string();
        HashableMessage::String(s)
    }
}

impl<'a> From<bool> for HashableMessage<'a> {
    fn from(value: bool) -> Self {
        match value {
            true => HashableMessage::String("true".to_string()),
            false => HashableMessage::String("false".to_string()),
        }
    }
}

impl<'a> From<Vec<HashableMessage<'a>>> for HashableMessage<'a> {
    fn from(value: Vec<HashableMessage<'a>>) -> Self {
        HashableMessage::Composite(value)
    }
}
impl<'a> From<&'a Vec<HashableMessage<'a>>> for HashableMessage<'a> {
    fn from(value: &'a Vec<HashableMessage<'a>>) -> Self {
        let res: Vec<&HashableMessage> = value.iter().collect();
        HashableMessage::CompositeR(res)
    }
}

impl<'a> From<&'a Vec<String>> for HashableMessage<'a> {
    fn from(value: &'a Vec<String>) -> Self {
        let l: Vec<HashableMessage> = value.iter().map(HashableMessage::from).collect();
        HashableMessage::from(l)
    }
}

impl<'a> From<&'a [String]> for HashableMessage<'a> {
    fn from(value: &'a [String]) -> Self {
        let l: Vec<HashableMessage> = value.iter().map(HashableMessage::from).collect();
        HashableMessage::from(l)
    }
}

impl<'a> From<&'a Vec<&'a String>> for HashableMessage<'a> {
    fn from(value: &'a Vec<&'a String>) -> Self {
        let l: Vec<HashableMessage> = value.iter().map(|s| HashableMessage::from(*s)).collect();
        HashableMessage::from(l)
    }
}

impl<'a> From<&'a Vec<ByteArray>> for HashableMessage<'a> {
    fn from(value: &'a Vec<ByteArray>) -> Self {
        let l: Vec<HashableMessage> = value.iter().map(HashableMessage::from).collect();
        HashableMessage::from(l)
    }
}

impl<'a> From<&'a Vec<MPInteger>> for HashableMessage<'a> {
    fn from(value: &'a Vec<MPInteger>) -> Self {
        let l: Vec<HashableMessage> = value.iter().map(HashableMessage::from).collect();
        HashableMessage::from(l)
    }
}

impl<'a> From<&'a Vec<&'a MPInteger>> for HashableMessage<'a> {
    fn from(value: &'a Vec<&'a MPInteger>) -> Self {
        let l: Vec<HashableMessage> = value.iter().map(|n| HashableMessage::from(*n)).collect();
        HashableMessage::from(l)
    }
}

impl<'a> From<&'a [MPInteger]> for HashableMessage<'a> {
    fn from(value: &'a [MPInteger]) -> Self {
        let l: Vec<HashableMessage> = value.iter().map(HashableMessage::from).collect();
        HashableMessage::from(l)
    }
}

impl<'a> From<Vec<&'a MPInteger>> for HashableMessage<'a> {
    fn from(value: Vec<&'a MPInteger>) -> Self {
        let l: Vec<HashableMessage> = value.iter().map(|n| HashableMessage::from(*n)).collect();
        HashableMessage::from(l)
    }
}

impl<'a> From<&'a Vec<usize>> for HashableMessage<'a> {
    fn from(value: &'a Vec<usize>) -> Self {
        let l: Vec<HashableMessage> = value.iter().map(HashableMessage::from).collect();
        HashableMessage::from(l)
    }
}

impl<'a> From<&'a Vec<Vec<MPInteger>>> for HashableMessage<'a> {
    fn from(value: &'a Vec<Vec<MPInteger>>) -> Self {
        let l: Vec<HashableMessage> = value.iter().map(HashableMessage::from).collect();
        HashableMessage::from(l)
    }
}

impl<'a> From<&'a Vec<Vec<usize>>> for HashableMessage<'a> {
    fn from(value: &'a Vec<Vec<usize>>) -> Self {
        let l: Vec<HashableMessage> = value.iter().map(HashableMessage::from).collect();
        HashableMessage::from(l)
    }
}

impl<'a> From<&'a Vec<Vec<String>>> for HashableMessage<'a> {
    fn from(value: &'a Vec<Vec<String>>) -> Self {
        let l: Vec<HashableMessage> = value.iter().map(HashableMessage::from).collect();
        HashableMessage::from(l)
    }
}

impl<'a> From<Vec<&'a Self>> for HashableMessage<'a> {
    fn from(value: Vec<&'a Self>) -> Self {
        HashableMessage::CompositeR(value)
    }
}

#[cfg(test)]
mod test {
    use super::super::{byte_array::Decode, integer::Hexa};
    use super::*;

    #[test]
    fn test_simple_byte_array() {
        let b = ByteArray::base64_decode(
            "t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaDssbzSibBsu/6iGtCOGEfz9zeNVs7ZRkDW7w09N75p0AYw=="
        ).unwrap();
        let r = HashableMessage::from(&b).recursive_hash();
        let e = ByteArray::base64_decode("0SHVZ9hTTmR+NRhanLPF/qPg3NmQbXyAzLYw9QVxYOg=").unwrap();
        assert_eq!(r, e);
    }

    #[test]
    fn test_mp_integer() {
        let i = MPInteger::from_hexa_string(
            "0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF324E7738926CFBE5F4BF8D8D8C31D763DA06C80ABB1185EB4F7C7B5757F5958490CFD47D7C19BB42158D9554F7B46BCED55C4D79FD5F24D6613C31C3839A2DDF8A9A276BCFBFA1C877C56284DAB79CD4C2B3293D20E9E5EAF02AC60ACC93ED874422A52ECB238FEEE5AB6ADD835FD1A0753D0A8F78E537D2B95BB79D8DCAEC642C1E9F23B829B5C2780BF38737DF8BB300D01334A0D0BD8645CBFA73A6160FFE393C48CBBBCA060F0FF8EC6D31BEB5CCEED7F2F0BB088017163BC60DF45A0ECB1BCD289B06CBBFEA21AD08E1847F3F7378D56CED94640D6EF0D3D37BE69D0063"
        ).unwrap();
        let r = HashableMessage::from(&i).recursive_hash();
        let e = ByteArray::base64_decode("YXHR0NvojiUMGz7RCTcO48ZQ1uqRtS64goB6XMFW01E=").unwrap();
        assert_eq!(r, e);
    }

    #[test]
    fn test_string() {
        let s = "test string".to_string();
        let r = HashableMessage::from(&s).recursive_hash();
        let e = ByteArray::base64_decode("m1a11iWW/Tcihy/IChyY51AO8UdZe48f5oRFh7RL+JQ=").unwrap();
        assert_eq!(r, e);
    }

    #[test]
    fn test_str() {
        let r = HashableMessage::from("test string").recursive_hash();
        let e = ByteArray::base64_decode("m1a11iWW/Tcihy/IChyY51AO8UdZe48f5oRFh7RL+JQ=").unwrap();
        assert_eq!(r, e);
    }

    #[test]
    fn test_mp_integer_list() {
        let inputs = [
            "0x41AFF17DA7F61150FCBC221E26D5BBEC1F540A3A3F13106FB45EB0E7C330C108AB338C525220A1D2D20EB77C642E7F360879A7B42BD2D191891F5A8CDBE7858407A7E7945A3518B0CC89A05BD3A61FD08235E0608F0AD678A99A385A668953A5591778CEBFCC8E3AF6F60DBA277320A58423FA436BEAACDEE2D5A2CDE86060BA8CF5BE70C4418E67B27FFEB96742FE6546C0ED533191B78BF88C8605D9ACF212016CB1735B1EC2ECC1491B73B82A5B348DB70A87FE0199899658CCD198CC53C7DD774D386A44867BB65EFF6704A6DD14AD462B13847B932FE4258C70F5FC20996FD9B2093EC0FD849070B5DDDDF741B8DFEFB972CFFE3A91E778CBEDE3A9CE1D",
            "0x35E854073500849CB2807B093D5F86176533B04DD81309D771A6461064E4A6E2B7F464D0502E9F2E2F5AD7AB4E225025E65A98CEEE2906C86158E7C432C4F50A149CD31A6C17CA1A000EC879B5CC0EF8E825EF8B83D4111D8AB59FCAB34694F112F5D3C2527F9121A50C95D975D3653972A9F17BFFBA26D542508EC57274202CCFF787EBC5E2E89F3EBEBFF17419B9338D47BF745901BE43D4A132FC503C9D07D7C3D3C35D303CD86C0F44B138E116CAA72B2DEFDA6D56BE841B980732EAE986710882143DAE385EE1832487F824A7AB404DFDFA903BEBDFC7682CE8D08F77B37E3B0AB99F40CAC2BA0EE8B6F64DE4BA3568A22359B114AE560656B8F59D0357",
            "0xA2A11C203F431AE713385CDF5F7346EF5A5E8B7B8CF971C947033978CF5F7263938D6B56754BAFBBCF8FC0A5CB2E0AF02D8433883326744E69247F0578A688A4225036F1D22D692ADA0C9515C3DE290797BE0E76FB04C9C17EF96E65F632329FC85C955C828A4DF5DF11962B3E24F32B7F87C47C0496F47ECF77C24C433740B4D3BCE077A7CEEE4EEE2E4B8D21E6DB21C05231EB1CB03D679D0D0B5D9E7BD205F9667FE6C18627E006191A987E5471E73D557B33FAD16D37C0B516D3948FE5B4690CE26059E6FC8B5853EE5AED99B6345206CCD5290CE0AC297163F57058A1ECE8718FBE8DAB9C2C5322D5726A16748F3F259B87FB00B1D54DDB063C7DBB8FF4",
        ];
        let bis: Vec<MPInteger> = inputs
            .iter()
            .map(|e| MPInteger::from_hexa_slice(e).unwrap())
            .collect();
        let r = HashableMessage::from(&bis).recursive_hash();
        let e = ByteArray::base64_decode("Qn1sWr2uZ87jwjeEoJa9zS6dc6S92oC0X83yxpyv2ZA=").unwrap();
        assert_eq!(r, e);
    }

    #[test]
    fn test_mp_integer_list_len1() {
        let inputs = [
            "0xA4D9B0B481FB03073E4B3EEE862FA2AA667AED37DD201FF41F786166C98D01AB3CEED0249FA1F12F23DEF203A98C53A294F5DE1A54A98EAA36F7232336FDFE89F28AD86789BCB67B5E41AFF9CE6EE5639A12B763D2A170E0B8208838079A622B11FC7DCDAC3DE178803E767028FEB607C2954834A8A53B400894E2CF7591D9E68CB987D2B5F05C5A799A38A513E53C451E6DF746C5C32FBAFE9AED6B8A1722AC15D40F1CA1DAC5F058618829514811F13516A18A4142D1B69830803A4910A89A5938491F75AFE9C07AC138CCB9B548814794A7B5A6E4F22CD2365FED5011A1E7DD26955958C8A9FCDEE31B9C6AABB6B50CC8E595144F4CCCAFFC74656DA135E3",
        ];
        let bis: Vec<MPInteger> = inputs
            .iter()
            .map(|e| MPInteger::from_hexa_slice(e).unwrap())
            .collect();
        let r = HashableMessage::from(&bis).recursive_hash();
        let e = ByteArray::base64_decode("+e9LVZg0L5uHLbnUv8pIVVm28y+QZMtfG1edAFx2oPM=").unwrap();
        assert_eq!(r, e);
    }

    #[test]
    fn test_mix_content() {
        let mut l: Vec<HashableMessage> = vec![];
        l.push(HashableMessage::from("common reference string"));
        let bi1 = MPInteger::from_hexa_string(
            "0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF324E7738926CFBE5F4BF8D8D8C31D763DA06C80ABB1185EB4F7C7B5757F5958490CFD47D7C19BB42158D9554F7B46BCED55C4D79FD5F24D6613C31C3839A2DDF8A9A276BCFBFA1C877C56284DAB79CD4C2B3293D20E9E5EAF02AC60ACC93ED874422A52ECB238FEEE5AB6ADD835FD1A0753D0A8F78E537D2B95BB79D8DCAEC642C1E9F23B829B5C2780BF38737DF8BB300D01334A0D0BD8645CBFA73A6160FFE393C48CBBBCA060F0FF8EC6D31BEB5CCEED7F2F0BB088017163BC60DF45A0ECB1BCD289B06CBBFEA21AD08E1847F3F7378D56CED94640D6EF0D3D37BE69D0063"
        ).unwrap();
        l.push(HashableMessage::from(&bi1));
        let bi2 = MPInteger::from_hexa_string(
            "0x5BF0A8B1457695355FB8AC404E7A79E3B1738B079C5A6D2B53C26C8228C867F799273B9C49367DF2FA5FC6C6C618EBB1ED0364055D88C2F5A7BE3DABABFACAC24867EA3EBE0CDDA10AC6CAAA7BDA35E76AAE26BCFEAF926B309E18E1C1CD16EFC54D13B5E7DFD0E43BE2B1426D5BCE6A6159949E9074F2F5781563056649F6C3A21152976591C7F772D5B56EC1AFE8D03A9E8547BC729BE95CADDBCEC6E57632160F4F91DC14DAE13C05F9C39BEFC5D98068099A50685EC322E5FD39D30B07FF1C9E2465DDE5030787FC763698DF5AE6776BF9785D84400B8B1DE306FA2D07658DE6944D8365DFF510D68470C23F9FB9BC6AB676CA3206B77869E9BDF34E8031"
        ).unwrap();
        l.push(HashableMessage::from(&bi2));
        let ba = ByteArray::base64_decode("YcOpYm5zaXRwcSBi").unwrap();
        l.push(HashableMessage::from(&ba));
        let r = HashableMessage::Composite(l).recursive_hash();
        let e = ByteArray::base64_decode("rHGUCWqWKTj9KBY3GgSeNEXZfraTDK+ZGIhlSxpVs5c=").unwrap();
        assert_eq!(r, e);
    }

    #[test]
    fn test_mixed_content_nested() {
        let mut nl: Vec<HashableMessage> = vec![];
        let bu1 = MPInteger::from_hexa_string("0x4").unwrap();
        nl.push(HashableMessage::from(&bu1));
        let bu2 = MPInteger::from_hexa_string(
            "0x3896D05A527747E840CEB0A10454DE39955529297AC4CB21010E9287A21F826FA7221215E1C7EE8362223DF51215A7F4CD14F158980154EE0794B599639A6FBC171A97F376A4DD95945C476F0DC6836FCEA68C9B28F901CE7F30DC03F406947E6245BF741650F5164BFC24F4B23948A5D6642C36D61016E63E943DB9717335EEB04373BFAE10BB4FB20EA9FD1BE48CA9A02B8E8C6639AD8E43D714ED16D4764D258E9A70BABD5497C09E148052C1C6A965F18F71F7B03385178B4991AA790611FA3B98E9C2F1EE1E0369F496A1D6928D718650513439D01898AAB87BC968F76D9DB8089809142A0C79A84C689D02314CEDE64F4C9615B79D49D2BE641BE8D4AB"
        ).unwrap();
        nl.push(HashableMessage::from(&bu2));
        let mut l: Vec<HashableMessage> = vec![];
        l.push(HashableMessage::from("common reference string"));
        let bu3 = MPInteger::from_hexa_string(
            "0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF324E7738926CFBE5F4BF8D8D8C31D763DA06C80ABB1185EB4F7C7B5757F5958490CFD47D7C19BB42158D9554F7B46BCED55C4D79FD5F24D6613C31C3839A2DDF8A9A276BCFBFA1C877C56284DAB79CD4C2B3293D20E9E5EAF02AC60ACC93ED874422A52ECB238FEEE5AB6ADD835FD1A0753D0A8F78E537D2B95BB79D8DCAEC642C1E9F23B829B5C2780BF38737DF8BB300D01334A0D0BD8645CBFA73A6160FFE393C48CBBBCA060F0FF8EC6D31BEB5CCEED7F2F0BB088017163BC60DF45A0ECB1BCD289B06CBBFEA21AD08E1847F3F7378D56CED94640D6EF0D3D37BE69D0063"
        ).unwrap();
        l.push(HashableMessage::from(&bu3));
        let bu4 = MPInteger::from_hexa_string(
            "0x5BF0A8B1457695355FB8AC404E7A79E3B1738B079C5A6D2B53C26C8228C867F799273B9C49367DF2FA5FC6C6C618EBB1ED0364055D88C2F5A7BE3DABABFACAC24867EA3EBE0CDDA10AC6CAAA7BDA35E76AAE26BCFEAF926B309E18E1C1CD16EFC54D13B5E7DFD0E43BE2B1426D5BCE6A6159949E9074F2F5781563056649F6C3A21152976591C7F772D5B56EC1AFE8D03A9E8547BC729BE95CADDBCEC6E57632160F4F91DC14DAE13C05F9C39BEFC5D98068099A50685EC322E5FD39D30B07FF1C9E2465DDE5030787FC763698DF5AE6776BF9785D84400B8B1DE306FA2D07658DE6944D8365DFF510D68470C23F9FB9BC6AB676CA3206B77869E9BDF34E8031"
        ).unwrap();
        l.push(HashableMessage::from(&bu4));
        let ba = ByteArray::base64_decode("YcOpYm5zaXRwcSBi").unwrap();
        l.push(HashableMessage::from(&ba));
        l.push(HashableMessage::Composite(nl));
        let r = HashableMessage::Composite(l).recursive_hash();
        let e = ByteArray::base64_decode("HYq9bWhqsm+/Sh8omWJGg2om5sQ2zosPIEhaIQ2m9GE=").unwrap();
        assert_eq!(r, e);
    }

    #[test]
    fn test_mixed_content_nested2() {
        let mut nl: Vec<HashableMessage> = vec![];
        let n = 4;
        nl.push(HashableMessage::from(&n));
        let bu2 = MPInteger::from_hexa_string(
            "0x3896D05A527747E840CEB0A10454DE39955529297AC4CB21010E9287A21F826FA7221215E1C7EE8362223DF51215A7F4CD14F158980154EE0794B599639A6FBC171A97F376A4DD95945C476F0DC6836FCEA68C9B28F901CE7F30DC03F406947E6245BF741650F5164BFC24F4B23948A5D6642C36D61016E63E943DB9717335EEB04373BFAE10BB4FB20EA9FD1BE48CA9A02B8E8C6639AD8E43D714ED16D4764D258E9A70BABD5497C09E148052C1C6A965F18F71F7B03385178B4991AA790611FA3B98E9C2F1EE1E0369F496A1D6928D718650513439D01898AAB87BC968F76D9DB8089809142A0C79A84C689D02314CEDE64F4C9615B79D49D2BE641BE8D4AB"
        ).unwrap();
        nl.push(HashableMessage::from(&bu2));
        let mut l: Vec<HashableMessage> = vec![];
        l.push(HashableMessage::from("common reference string"));
        let bu3 = MPInteger::from_hexa_string(
            "0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF324E7738926CFBE5F4BF8D8D8C31D763DA06C80ABB1185EB4F7C7B5757F5958490CFD47D7C19BB42158D9554F7B46BCED55C4D79FD5F24D6613C31C3839A2DDF8A9A276BCFBFA1C877C56284DAB79CD4C2B3293D20E9E5EAF02AC60ACC93ED874422A52ECB238FEEE5AB6ADD835FD1A0753D0A8F78E537D2B95BB79D8DCAEC642C1E9F23B829B5C2780BF38737DF8BB300D01334A0D0BD8645CBFA73A6160FFE393C48CBBBCA060F0FF8EC6D31BEB5CCEED7F2F0BB088017163BC60DF45A0ECB1BCD289B06CBBFEA21AD08E1847F3F7378D56CED94640D6EF0D3D37BE69D0063"
        ).unwrap();
        l.push(HashableMessage::from(&bu3));
        let bu4 = MPInteger::from_hexa_string(
            "0x5BF0A8B1457695355FB8AC404E7A79E3B1738B079C5A6D2B53C26C8228C867F799273B9C49367DF2FA5FC6C6C618EBB1ED0364055D88C2F5A7BE3DABABFACAC24867EA3EBE0CDDA10AC6CAAA7BDA35E76AAE26BCFEAF926B309E18E1C1CD16EFC54D13B5E7DFD0E43BE2B1426D5BCE6A6159949E9074F2F5781563056649F6C3A21152976591C7F772D5B56EC1AFE8D03A9E8547BC729BE95CADDBCEC6E57632160F4F91DC14DAE13C05F9C39BEFC5D98068099A50685EC322E5FD39D30B07FF1C9E2465DDE5030787FC763698DF5AE6776BF9785D84400B8B1DE306FA2D07658DE6944D8365DFF510D68470C23F9FB9BC6AB676CA3206B77869E9BDF34E8031"
        ).unwrap();
        l.push(HashableMessage::from(&bu4));
        let ba = ByteArray::base64_decode("YcOpYm5zaXRwcSBi").unwrap();
        l.push(HashableMessage::from(&ba));
        l.push(HashableMessage::Composite(nl));
        let r = HashableMessage::Composite(l).recursive_hash();
        let e = ByteArray::base64_decode("HYq9bWhqsm+/Sh8omWJGg2om5sQ2zosPIEhaIQ2m9GE=").unwrap();
        assert_eq!(r, e);
    }

    #[test]
    fn test_hashed() {
        let mut nl: Vec<HashableMessage> = vec![];
        let bu1 = MPInteger::from_hexa_string("0x4").unwrap();
        nl.push(HashableMessage::Hashed(
            HashableMessage::from(&bu1).recursive_hash(),
        ));
        let bu2 = MPInteger::from_hexa_string(
            "0x3896D05A527747E840CEB0A10454DE39955529297AC4CB21010E9287A21F826FA7221215E1C7EE8362223DF51215A7F4CD14F158980154EE0794B599639A6FBC171A97F376A4DD95945C476F0DC6836FCEA68C9B28F901CE7F30DC03F406947E6245BF741650F5164BFC24F4B23948A5D6642C36D61016E63E943DB9717335EEB04373BFAE10BB4FB20EA9FD1BE48CA9A02B8E8C6639AD8E43D714ED16D4764D258E9A70BABD5497C09E148052C1C6A965F18F71F7B03385178B4991AA790611FA3B98E9C2F1EE1E0369F496A1D6928D718650513439D01898AAB87BC968F76D9DB8089809142A0C79A84C689D02314CEDE64F4C9615B79D49D2BE641BE8D4AB"
        ).unwrap();
        nl.push(HashableMessage::from(&bu2));
        let mut l: Vec<HashableMessage> = vec![];
        l.push(HashableMessage::from("common reference string"));
        let bu3 = MPInteger::from_hexa_string(
            "0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF324E7738926CFBE5F4BF8D8D8C31D763DA06C80ABB1185EB4F7C7B5757F5958490CFD47D7C19BB42158D9554F7B46BCED55C4D79FD5F24D6613C31C3839A2DDF8A9A276BCFBFA1C877C56284DAB79CD4C2B3293D20E9E5EAF02AC60ACC93ED874422A52ECB238FEEE5AB6ADD835FD1A0753D0A8F78E537D2B95BB79D8DCAEC642C1E9F23B829B5C2780BF38737DF8BB300D01334A0D0BD8645CBFA73A6160FFE393C48CBBBCA060F0FF8EC6D31BEB5CCEED7F2F0BB088017163BC60DF45A0ECB1BCD289B06CBBFEA21AD08E1847F3F7378D56CED94640D6EF0D3D37BE69D0063"
        ).unwrap();
        l.push(HashableMessage::from(&bu3));
        let bu4 = MPInteger::from_hexa_string(
            "0x5BF0A8B1457695355FB8AC404E7A79E3B1738B079C5A6D2B53C26C8228C867F799273B9C49367DF2FA5FC6C6C618EBB1ED0364055D88C2F5A7BE3DABABFACAC24867EA3EBE0CDDA10AC6CAAA7BDA35E76AAE26BCFEAF926B309E18E1C1CD16EFC54D13B5E7DFD0E43BE2B1426D5BCE6A6159949E9074F2F5781563056649F6C3A21152976591C7F772D5B56EC1AFE8D03A9E8547BC729BE95CADDBCEC6E57632160F4F91DC14DAE13C05F9C39BEFC5D98068099A50685EC322E5FD39D30B07FF1C9E2465DDE5030787FC763698DF5AE6776BF9785D84400B8B1DE306FA2D07658DE6944D8365DFF510D68470C23F9FB9BC6AB676CA3206B77869E9BDF34E8031"
        ).unwrap();
        l.push(HashableMessage::from(&bu4));
        let ba = ByteArray::base64_decode("YcOpYm5zaXRwcSBi").unwrap();
        l.push(HashableMessage::from(&ba));
        l.push(HashableMessage::Composite(nl));
        let r = HashableMessage::Composite(l).recursive_hash();
        let e = ByteArray::base64_decode("HYq9bWhqsm+/Sh8omWJGg2om5sQ2zosPIEhaIQ2m9GE=").unwrap();
        assert_eq!(r, e);
    }

    #[test]
    fn test_vec_vec_integer() {
        let data = vec![
            vec![MPInteger::from(2u8)],
            vec![MPInteger::from(3u8), MPInteger::from(4u8)],
            vec![MPInteger::from(5u8)],
        ];
        let mut res: Vec<HashableMessage> = vec![];
        let v1 = vec![MPInteger::from(2u8)];
        let v2 = vec![MPInteger::from(3u8), MPInteger::from(4u8)];
        let v3 = vec![MPInteger::from(5u8)];
        res.push(HashableMessage::from(&v1));
        res.push(HashableMessage::from(&v2));
        res.push(HashableMessage::from(&v3));
        assert_eq!(HashableMessage::from(&data), HashableMessage::from(res))
    }

    #[test]
    fn test_zq_test_string() {
        let q = MPInteger::from_hexa_string(
            "0x5BF0A8B1457695355FB8AC404E7A79E3B1738B079C5A6D2B53C26C8228C867F799273B9C49367DF2FA5FC6C6C618EBB1ED0364055D88C2F5A7BE3DABABFACAC24867EA3EBE0CDDA10AC6CAAA7BDA35E76AAE26BCFEAF926B309E18E1C1CD16EFC54D13B5E7DFD0E43BE2B1426D5BCE6A6159949E9074F2F5781563056649F6C3A21152976591C7F772D5B56EC1AFE8D03A9E8547BC729BE95CADDBCEC6E57632160F4F91DC14DAE13C05F9C39BEFC5D98068099A50685EC322E5FD39D30B07FF1C9E2465DDE5030787FC763698DF5AE6776BF9785D84400B8B1DE306FA2D07658DE6944D8365DFF510D68470C23F9FB9BC6AB676CA3206B77869E9BDF3380470C368DF93ADCD920EF5B23A4D23EFEFDCB31961F5830DB2395DFC26130A2724E1682619277886F289E9FA88A5C5AE9BA6C9E5C43CE3EA97FEB95D0557393BED3DD0DA578A446C741B578A432F361BD5B43B7F3485AB88909C1579A0D7F4A7BBDE783641DC7FAB3AF84BC83A56CD3C3DE2DCDEA5862C9BE9F6F261D3C9CB20CE6B"
        ).unwrap();
        let s = "test string".to_string();
        let r = HashableMessage::from(&s).recursive_hash_to_zq(&q);
        let e = MPInteger::from_hexa_string(
            "0x687EF94C9F5D22F5547A017BB693FE7A2B655AD995EB29B03729BE8F7649EFBA67BC64450362B3F02A19D9868658546D627D348D490FBCC523C735B0BAC53486C740EFB0D1F63163A644C611938F8F7572210AE04A4C6873FADC80A40A55180EC0043B3FD0F787190406FF0277BEF5C1D4BBCE921865183465BDE79CBAE939AAA6C961BCDAD0DAEC05D270C1BC37EF770D002B9E1E7528191882D736E2772ACE46BB0741C11A44EE062CDC9A43265DA47A7C6CFB32256707F2F82B9A4B9E7942E780A17DCDDC7153851F65AC269FE9F0751F526093CB5A84A640B6409FCD52F9D08331AF68A8AC38C9B2A607E6D7BFE7E49CBBA2275B9D27CC81C4EBC9FF67FAE4B3AA5BC5DAE2751F2539B9971FBD1D9A5A78E0EE2AFBC870E4F2037580887024AB53CF66996852507DBF1CCD06B0B2309F10F8031E8EF23D5225717FC78E118E01383E6222CCE26EFD7EB516D75AC9F8F1585FF19C5A540D36E94187CDC167E60767EF8851B15A327FD71DCF05D97D22958B8FD4DC47019C44BF400DB689C"
        ).unwrap();
        assert_eq!(r, e)
    }

    #[test]
    fn test_zq_test_bytearray() {
        let q = MPInteger::from_hexa_string(
            "0x5BF0A8B1457695355FB8AC404E7A79E3B1738B079C5A6D2B53C26C8228C867F799273B9C49367DF2FA5FC6C6C618EBB1ED0364055D88C2F5A7BE3DABABFACAC24867EA3EBE0CDDA10AC6CAAA7BDA35E76AAE26BCFEAF926B309E18E1C1CD16EFC54D13B5E7DFD0E43BE2B1426D5BCE6A6159949E9074F2F5781563056649F6C3A21152976591C7F772D5B56EC1AFE8D03A9E8547BC729BE95CADDBCEC6E57632160F4F91DC14DAE13C05F9C39BEFC5D98068099A50685EC322E5FD39D30B07FF1C9E2465DDE5030787FC763698DF5AE6776BF9785D84400B8B1DE306FA2D07658DE6944D8365DFF510D68470C23F9FB9BC6AB676CA3206B77869E9BDF3380470C368DF93ADCD920EF5B23A4D23EFEFDCB31961F5830DB2395DFC26130A2724E1682619277886F289E9FA88A5C5AE9BA6C9E5C43CE3EA97FEB95D0557393BED3DD0DA578A446C741B578A432F361BD5B43B7F3485AB88909C1579A0D7F4A7BBDE783641DC7FAB3AF84BC83A56CD3C3DE2DCDEA5862C9BE9F6F261D3C9CB20CE6B"
        ).unwrap();
        let s = ByteArray::base64_decode("q83vASNFZ4k=").unwrap();
        let r = HashableMessage::from(&s).recursive_hash_to_zq(&q);
        let e = MPInteger::from_hexa_string(
            "0x384A8B51CBB6A6B5A7475AF118698633368E65349C00C2170D98DF51155942805F6CD42F5EAA6E71D952D090BD9A14846B5772D1360ABBD478BEBC306255FDDAD04082957FB4C04D8C1BBB17107DE5ACC5E456F834E01B562FBCDC5A961B52442F81BD3BEBF5C33229202425CDD36609012F7ECA22FAF45962DB0DF27764C7A7114EAFA2C054501DC5FECD01A1E40A54CCE52BABEFB86C398C8B4D913CCC977F5086A53784976B9A2FDC5B14AB5650630D1F00B2E5DB31404EBA7077EF8D028EE73D0A78BA8E5F482FDD364B28D68DB1641EDB18728156BF8018FF8DBAB45B068E599B4758E6B63C390FA5D4B307C64C8CD44A2D788BD76E0DC0DEECA0CDDDF760CAC77B90AE99FC13AAEDDCAA3053DBAF086B31DAA493D49409C373B796F0330A41ED5F7265BE2E3ED998F9E1B846E76E12DDF6DB2D2F1A161B65F92F19DBE8DA0DAFA61A16EAF8774D61DE2B8489B3644F43D0D16FBCAE73787ECD5A3E4AFCD761DF11351A03A158889E4E360187627CA1D76224CE53E502D86C8420C2ABBD"
        ).unwrap();
        assert_eq!(r, e)
    }

    #[test]
    fn test_zq_test_integer() {
        let q = MPInteger::from_hexa_string(
            "0x5BF0A8B1457695355FB8AC404E7A79E3B1738B079C5A6D2B53C26C8228C867F799273B9C49367DF2FA5FC6C6C618EBB1ED0364055D88C2F5A7BE3DABABFACAC24867EA3EBE0CDDA10AC6CAAA7BDA35E76AAE26BCFEAF926B309E18E1C1CD16EFC54D13B5E7DFD0E43BE2B1426D5BCE6A6159949E9074F2F5781563056649F6C3A21152976591C7F772D5B56EC1AFE8D03A9E8547BC729BE95CADDBCEC6E57632160F4F91DC14DAE13C05F9C39BEFC5D98068099A50685EC322E5FD39D30B07FF1C9E2465DDE5030787FC763698DF5AE6776BF9785D84400B8B1DE306FA2D07658DE6944D8365DFF510D68470C23F9FB9BC6AB676CA3206B77869E9BDF3380470C368DF93ADCD920EF5B23A4D23EFEFDCB31961F5830DB2395DFC26130A2724E1682619277886F289E9FA88A5C5AE9BA6C9E5C43CE3EA97FEB95D0557393BED3DD0DA578A446C741B578A432F361BD5B43B7F3485AB88909C1579A0D7F4A7BBDE783641DC7FAB3AF84BC83A56CD3C3DE2DCDEA5862C9BE9F6F261D3C9CB20CE6B"
        ).unwrap();
        let s = MPInteger::from_hexa_string(
            "0xE0D1E56B15F4DB2B84162354AC2518FB020BDC0AEB1E0ED0FDE5E989EA38696BA821AEF776EEE28C9296B712577933812E2DDFD6F17192329E21CE964407E137DE522B745C807EBEC8EEB2CE9896B76FA926CD592A33CF32816C55ABBB90FD67DDBC2BD4EA633B3B8CA888C9F76773120EBC92C6327A2067B4B596BD403B2450E811EFB5499C7C7C91994395F9C6C57ABA124D1AA649272C72C7FE71049F6794B059A5ACB1E6B3092DCCE5224740C5E38C382FE98480D3CDAC483D5E9CD7A1B9F7B9BC52A66B0B7231510108BBE22CE53EDE06C44CFDC0657E0BACBFA6B9EF7B1A5F74C5D3FB39C388E67F10DCD5C15EB0DB79B52CC9B9DA3EAA5530242BBE19BAAC5BCC9AEFD03DD6BDB1943562D03D1E0EF3C320A2FCA83D718E92BC807424D0CF3D753FC49C6EB8453754E26C072B00232166848ECC4F7AA137BD068EE4110917FE752E83FC332333055C67680BC78C9E8F77C918B9C695BDB4BBFB9B9AFF85C5D77D5106B682640CD159B7FFD7BDBC5ECC908D47CD73ECF95B35D385D19"
        ).unwrap();
        let r = HashableMessage::from(&s).recursive_hash_to_zq(&q);
        let e = MPInteger::from_hexa_string(
            "0x54A8D780AFDEEA94AB69D8BE217D75F3EE504AA35E2315451B0B1628D40577932845754774D443E390FEAE84C1E23F9CDE749CDE420923AE79B9E2FD588BC8A6A49C4FB1C4A360C6FD8BFFF387C76D84E52F0F3F990F43E7F92E3A90BE6A0972CE71CC62B41A900752BC4747F3E9F2E3B0855EA31EE31D0B475C296B49B70D37A1A07E66DF9B26A68EDF2B2A9AFCE721785BA76BAA4CB2806547573C53FFE8BA9862F0D8A07DBC7D8761BEFF5E6542C5EC94ECF954628DF01161FD4AA735356FA3F3C6442C240E6F348184C078C6B104E90D83D1567A847C7CD1F06D856534DDCC7CE91EE2D946ED0E1BD24C73F599766FBC0A0779BCD739D4EA3A950058CB2383367D13F7DA3965D26E6243A04C132867D52905B1FBC8240CAFEDF2F357DDD68B8D210224D6E13AE379BAFA144FB6F4ABD9083B4B10AD8936AC671B6BFF75B96A8733E8F36836AF695EED60722AD5C98D9C62CB3EE3DA580DBD15441A03FAB53F2DF2D589598F5B42E2C8044C3A2B51DE6192ED6ABBA919B6B7AB5A3085CADB"
        ).unwrap();
        assert_eq!(r, e)
    }

    #[test]
    fn test_zq_mixed_content() {
        let q = MPInteger::from_hexa_string(
            "0x5BF0A8B1457695355FB8AC404E7A79E3B1738B079C5A6D2B53C26C8228C867F799273B9C49367DF2FA5FC6C6C618EBB1ED0364055D88C2F5A7BE3DABABFACAC24867EA3EBE0CDDA10AC6CAAA7BDA35E76AAE26BCFEAF926B309E18E1C1CD16EFC54D13B5E7DFD0E43BE2B1426D5BCE6A6159949E9074F2F5781563056649F6C3A21152976591C7F772D5B56EC1AFE8D03A9E8547BC729BE95CADDBCEC6E57632160F4F91DC14DAE13C05F9C39BEFC5D98068099A50685EC322E5FD39D30B07FF1C9E2465DDE5030787FC763698DF5AE6776BF9785D84400B8B1DE306FA2D07658DE6944D8365DFF510D68470C23F9FB9BC6AB676CA3206B77869E9BDF3380470C368DF93ADCD920EF5B23A4D23EFEFDCB31961F5830DB2395DFC26130A2724E1682619277886F289E9FA88A5C5AE9BA6C9E5C43CE3EA97FEB95D0557393BED3DD0DA578A446C741B578A432F361BD5B43B7F3485AB88909C1579A0D7F4A7BBDE783641DC7FAB3AF84BC83A56CD3C3DE2DCDEA5862C9BE9F6F261D3C9CB20CE6B"
        ).unwrap();
        let v = vec![
            HashableMessage::from("test string".to_string()),
            HashableMessage::from(ByteArray::base64_decode("q83vASNFZ4k=").unwrap()),
            HashableMessage::from(
                MPInteger::from_hexa_string(
                    "0x12956ABFFD9522888502E77884C7DF9D659BF4F93D908E01E04B56693E7A73D75AB513F16F805F70FE3D20404273E4E1611893C682EA1AE50E1C56A83F6ECC1A8580AE96568CD7412B6D70F9B1979CF52CAD3D2DDD9BCF8C3DB027E1E0B316B0B94D753CADC38F179888365382964006CF4EF543FDE8C2A4F138933502A250E98D0B13B871EE046E8A4656D2C5563A910E613D603E3A5DEFC941062530C0B0F02DBA35C1CEE7FF33E62E617B20BAC3499E33BA66BAC64A4D5EB63683089781BA0ECF82557164535ECDC8E26FE104ECF458D81BD25D55FB12B533B940C73D36F903FD4A5993A7535C62B00E2886816BB642F832D98DE8081853979652476331E52EB5FB9BC62081121748896623638FA4F5397FB1B203774F247B4A7A6350A671B2AE37CBCAC931DE417047E38C2218BD8EC4909E7D41B30A5D5E9C9788A7E866FA5FFAB69E0E815BFFB3F244503DE422F962B61C6881FFC3A4D027C4C1C4F285CAD46C6B4F25D2DCA2D81316E9C86623E5C71C56C0BDCC9C9C8E074BC5A3B746"
                ).unwrap()
            )
        ];
        let r = HashableMessage::from(&v).recursive_hash_to_zq(&q);
        let e = MPInteger::from_hexa_string(
            "0x34B564EAF73C3E0CD6D957052933E542013D4AB46C35B769F7038D6F719FDF037272D7E930002437FA7594B011DB9A652D7BF640282D96BF6C720B574D2DB8CBE387ABD7FB09E0902ECB1C9FEB20792426DB9DBE8D477065F74C950A82FC51E68A3D5094F6F55DE05B4E6876D9A7BFFA5F4C4221C93953D3FC7B80C53E0BCA164A058EB2291478E58C53AF2D5A32F6CD292C9650EEEA5D847E3D5C78B9A2182D15B5FD7480CDC7CD561E273CD6F5AE8350C988CD52DABC658AD15347B9A0E4C2EECE1462C267A5A2F3196356D3BAA5EB9952BC48AE8B8B85946E2F8C34D03014DB1DC55B0F147FECA4B3F5AE04B0350105CD8D8764F44558262AB59344FD4084754473BE90D36B718141E05B7467565A95CFFDE16860F06440A736446152BFEF5D36262F85FE719E9493652A3426FEB1AFBF636C5911C5C00C0F1FE2135FCF35C599B4905A8C3D659631EC4E1FF26D177D391C2A76D1F9E116143B00D5A6DEAFBD1CCD7B02D71FB08195860079934A4C18F4C3FB59790B83F5C71F00E1FA9D7F"
        ).unwrap();
        assert_eq!(r, e)
    }

    #[test]
    fn test_zq_nested_mixed_content() {
        let q = MPInteger::from_hexa_string(
            "0x5BF0A8B1457695355FB8AC404E7A79E3B1738B079C5A6D2B53C26C8228C867F799273B9C49367DF2FA5FC6C6C618EBB1ED0364055D88C2F5A7BE3DABABFACAC24867EA3EBE0CDDA10AC6CAAA7BDA35E76AAE26BCFEAF926B309E18E1C1CD16EFC54D13B5E7DFD0E43BE2B1426D5BCE6A6159949E9074F2F5781563056649F6C3A21152976591C7F772D5B56EC1AFE8D03A9E8547BC729BE95CADDBCEC6E57632160F4F91DC14DAE13C05F9C39BEFC5D98068099A50685EC322E5FD39D30B07FF1C9E2465DDE5030787FC763698DF5AE6776BF9785D84400B8B1DE306FA2D07658DE6944D8365DFF510D68470C23F9FB9BC6AB676CA3206B77869E9BDF3380470C368DF93ADCD920EF5B23A4D23EFEFDCB31961F5830DB2395DFC26130A2724E1682619277886F289E9FA88A5C5AE9BA6C9E5C43CE3EA97FEB95D0557393BED3DD0DA578A446C741B578A432F361BD5B43B7F3485AB88909C1579A0D7F4A7BBDE783641DC7FAB3AF84BC83A56CD3C3DE2DCDEA5862C9BE9F6F261D3C9CB20CE6B"
        ).unwrap();
        let s = vec![
            HashableMessage::from("test string".to_string()),
            HashableMessage::from(
                vec![
                    HashableMessage::from(ByteArray::base64_decode("q83vASNFZ4k=").unwrap()),
                    HashableMessage::from(
                        MPInteger::from_hexa_string(
                            "0x43282C01643696786C02BC07DB19F85AC1DE028C369F330C433D2854359DCA2960FD592CB2A73681BFB042F82718A802A96A56E089F716B50E425B1113B00A4DCDFE46478F5C8EDF971A999EEDB139BD321665247DC35DFA73D534F8E09FCB1BEF3F9801EEF06B5427735ECF2D1C0A790BCD33430CD215B1A9A68AE19C43BA6F643D1110CFC3990C64834629908565779EAE1268C00DAE10DB7E8D5D07CB1C235F55ADA28C09DF0BF5242DF2D2843792CC79BA1C429992F0BE7D13D4C178646046A9BF8AFCA94E6F18E1B1297BD9F2301C16BF956150E89741C5691346B5AD1B8CFEA1E8B7E35FFD46211FC869A51CEEDDEF8E9716EB3FB6738AA3DF080462EAFA0077863479E97B8EF49D1C8DD7CC1EACCF5797D37B342CE998F59C7CECE6B03DED01726286436C911FCE6B13F6BF4C2AE77F9EE501667B6F21E23AA2B636C9794790C4860DC8AE088109C083CCE605F16509ADF978B10C817DD42B0F5595AE5EAAD18235779EB887E2C410EA24E259B574384BD0F7889002C719F2E831AB83"
                        ).unwrap()
                    )
                ]
            )
        ];
        let r = HashableMessage::from(&s).recursive_hash_to_zq(&q);
        let e = MPInteger::from_hexa_string(
            "0x1674E16AA33640F120B61D420DDF2CD8608B0E45815467C897E42BCBBE3EC864351DA4AF6AAC9A1DBC79D5CD475D1A189A8632431F6754D75DCE3B063C3F0DB7A85266927559A480F04A86A6DB7778EB5DFBBEC459C865EF19B1D3C2CA7B6CEAFFC6F7B2183BD70AED9A053C3B0CBDC118BED8CB163EDE885A62E130B78C6EF2D0C4C8DCE46AB123F9225008953A299DAD05A5DE12431DB812C3FD6597751F6C5BB02E6C193EA6900DB682DF51F86E8D08E08EB362B3859CC0401205AA53FE9A2156B1B70D365C7168B26B3957BBBAEC976E878E4EB2937679391416D815EAAC2AB916063AB550F76CC3066772640CFAAB0DDD9393AC67B12605D5EB0792818478251891A1D75FD56CE8F3B68E5165A6BDA2ECCC5E09734359BC36BA6055308D5AA059EF1C7DAED51CE28ACAB30CD8BB5B94B0D69A87A1B90C5D26A8693083B80475B3857AF06C58EC5013804AC7EA57AAA16D4E474AC3B4F4EBBC6C5766CC20B130F23AE29D1E352E2B6E86083C11BA50FFF1770452AC11058FD7854408F3C5"
        ).unwrap();
        assert_eq!(r, e)
    }
}
