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

//! Implementation of the struct ByteArray that is used over the crate and for cryptographic functions

use crate::{integer::ToByteArrayError, ConstantsTrait, Integer, ToByteArryTrait};
use data_encoding::{DecodeError, BASE32, BASE64, HEXUPPER};
use num_traits::Pow;
use std::fmt::{Debug, Display};
use thiserror::Error;

#[derive(Error, Debug)]
#[error(transparent)]
pub struct ByteArrayError(#[from] ByteArrayErrorRepr);

#[derive(Error, Debug)]
enum ByteArrayErrorRepr {
    #[error(transparent)]
    DecodeErrorInBase(#[from] DecodeErrorInBase),
    #[error(transparent)]
    CutToBitLengthIndexError(#[from] CutToBitLengthIndexError),
    #[error(transparent)]
    FromIntegerError(#[from] FromIntegerError),
}

/// Error decoding a string to in a given base
#[derive(Error, Debug)]
#[error("Error decoding {orig} in base {base}")]
struct DecodeErrorInBase {
    orig: String,
    base: u8,
    source: DecodeError,
}

/// Error cutting a [ByteArray] to bit lenngth
#[derive(Error, Debug)]
#[error(
    "Error in cut_bit_length for {ba}: the index {index} must be between 1 and 8*{}",
    ba.len()
)]
struct CutToBitLengthIndexError {
    index: usize,
    ba: ByteArray,
}

/// Error getting [ByteArray] from [Integer]
#[derive(Error, Debug)]
enum FromIntegerError {
    #[error("Error try_from Integer")]
    ToByteArrayError { source: ToByteArrayError },
}

/// ByteArray represent a byte of arrays
#[derive(Clone, PartialEq, Eq)]
pub struct ByteArray {
    inner: Vec<u8>,
}

/// Trait to encode in string in different bases
///
/// ```
/// use rust_ev_crypto_primitives::EncodeTrait;
/// use rust_ev_crypto_primitives::ByteArray;
/// let ba = ByteArray::from_bytes(b"\x41").base64_encode().unwrap();
/// assert_eq!(ba, "QQ==");
/// ```
pub trait EncodeTrait {
    type Error: std::error::Error;

    /// Code to base16 according specifications
    fn base16_encode(&self) -> Result<String, Self::Error>;

    /// Code to base32 according specifications
    fn base32_encode(&self) -> Result<String, Self::Error>;

    /// Code to base64 according specifications
    fn base64_encode(&self) -> Result<String, Self::Error>;
}

/// Trait to decode from string in different bases
///
/// ```
/// use rust_ev_crypto_primitives::DecodeTrait;
/// use rust_ev_crypto_primitives::ByteArray;
/// let ba_res = ByteArray::base32_decode("MA======");
/// assert!(ba_res.is_ok());
/// assert_eq!(ba_res.unwrap().to_bytes(), b"\x60");
/// ```
pub trait DecodeTrait: Sized {
    type Error: std::error::Error + Sized;

    /// Code from string in base16 according specifications. The letters are in upper.
    ///
    /// # Error
    /// Return [ByteArrayError] if decode not possible
    fn base16_decode(s: &str) -> Result<Self, Self::Error>;

    /// Code from string in base32 according specifications.
    ///
    /// # Error
    /// Return [ByteArrayError] if decode not possible
    fn base32_decode(s: &str) -> Result<Self, Self::Error>;

    /// Code from string in base32 according specifications.
    ///
    /// # Error
    /// Return [ByteArrayError] if decode not possible
    fn base64_decode(s: &str) -> Result<Self, Self::Error>;

    fn base_64_decode_vector(vs: &[String]) -> Result<Vec<Self>, Self::Error> {
        vs.iter()
            .map(|s| Self::base64_decode(s))
            .collect::<Result<Vec<_>, _>>()
    }
}

impl ByteArray {
    /// Create an empty Bytearray (only with 0)
    pub fn new() -> Self {
        ByteArray { inner: vec![0] }
    }

    /// ByteArray from a slice of bytes
    pub fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return ByteArray::default();
        }
        Self {
            inner: bytes.to_vec(),
        }
    }

    /// ByteArray into Integer
    pub fn into_integer(&self) -> Integer {
        let int_256 = Integer::from(256u32);
        self.inner
            .iter()
            .fold(Integer::zero().clone(), |acc, b| b + acc * &int_256)
    }

    /// Len of the ByteArray in bytes
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// ByteArray to bytes
    pub fn to_bytes(&self) -> &[u8] {
        self.inner.as_slice()
    }

    /// Extend other to self
    ///
    /// self will changed and extend. other is cloned at the end of self
    pub fn extend(&mut self, other: &ByteArray) -> &ByteArray {
        self.inner.extend_from_slice(other.inner.as_slice());
        self
    }

    /// Append and return a new one
    ///
    /// The new one is the concatenation of self and other. self and other remain unchanged
    pub fn new_append(&self, other: &ByteArray) -> ByteArray {
        let mut res = self.clone();
        res.extend(other);
        res
    }

    /// Create a new ByteArray prepending a byte
    pub fn new_prepend_byte(&self, byte: u8) -> ByteArray {
        let mut res = self.clone();
        res.inner.insert(0, byte);
        res
    }

    /// Cut the byte array to given bit length according to the specifications of Swiss Post (Algorithm 3.1)
    ///
    /// # Error
    /// Return [ByteArrayError] if the conditions to cut are not satisfied (see algorithm)
    pub fn cut_bit_length(&self, n: usize) -> Result<ByteArray, ByteArrayError> {
        if n > 8 * self.len() {
            return Err(ByteArrayError::from(ByteArrayErrorRepr::from(
                CutToBitLengthIndexError {
                    index: n,
                    ba: self.clone(),
                },
            )));
        }
        let upper_b = self.to_bytes();
        let upper_n = self.len();
        let length = n.div_ceil(8);
        let offset = upper_n - length;
        let mut upper_b_prime: Vec<u8> = vec![];
        for i in 0..length {
            upper_b_prime.push(upper_b[offset + i]);
        }
        if n % 8 != 0 {
            upper_b_prime[0] = upper_b[offset] & (Pow::pow(2u8, n % 8) - 1);
        }
        Ok(ByteArray::from(&upper_b_prime))
    }
}

impl EncodeTrait for ByteArray {
    type Error = ByteArrayError;

    fn base16_encode(&self) -> Result<String, Self::Error> {
        Ok(HEXUPPER.encode(&self.inner))
    }

    fn base32_encode(&self) -> Result<String, Self::Error> {
        Ok(BASE32.encode(&self.inner))
    }

    fn base64_encode(&self) -> Result<String, Self::Error> {
        Ok(BASE64.encode(&self.inner))
    }
}

impl DecodeTrait for ByteArray {
    type Error = ByteArrayError;

    fn base16_decode(s: &str) -> Result<Self, Self::Error> {
        HEXUPPER
            .decode(s.as_bytes())
            .map_err(|e| DecodeErrorInBase {
                orig: s.to_string(),
                base: 16,
                source: e,
            })
            .map_err(ByteArrayErrorRepr::from)
            .map_err(ByteArrayError::from)
            .map(|r| Self::from(&r))
    }

    fn base32_decode(s: &str) -> Result<Self, Self::Error> {
        BASE32
            .decode(s.as_bytes())
            .map_err(|e| DecodeErrorInBase {
                orig: s.to_string(),
                base: 32,
                source: e,
            })
            .map_err(ByteArrayErrorRepr::from)
            .map_err(ByteArrayError::from)
            .map(|r| Self::from(&r))
    }

    fn base64_decode(s: &str) -> Result<Self, Self::Error> {
        BASE64
            .decode(s.as_bytes())
            .map_err(|e| DecodeErrorInBase {
                orig: s.to_string(),
                base: 64,
                source: e,
            })
            .map_err(ByteArrayErrorRepr::from)
            .map_err(ByteArrayError::from)
            .map(|r| Self::from(&r))
    }
}

impl Default for ByteArray {
    fn default() -> Self {
        ByteArray::new()
    }
}

impl Debug for ByteArray {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}

impl Display for ByteArray {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.base16_encode().unwrap())
    }
}

impl TryFrom<&Integer> for ByteArray {
    type Error = ByteArrayError;

    fn try_from(value: &Integer) -> Result<Self, Self::Error> {
        value
            .to_byte_array()
            .map_err(|e| FromIntegerError::ToByteArrayError { source: e })
            .map_err(ByteArrayErrorRepr::FromIntegerError)
            .map_err(ByteArrayError)
    }
}

impl From<&usize> for ByteArray {
    fn from(value: &usize) -> Self {
        ByteArray::try_from(&Integer::from(*value)).unwrap()
    }
}
impl From<&Vec<u8>> for ByteArray {
    fn from(bytes: &Vec<u8>) -> Self {
        if bytes.is_empty() {
            ByteArray::default()
        } else {
            ByteArray {
                inner: (*bytes.clone()).to_vec(),
            }
        }
    }
}

impl From<&str> for ByteArray {
    fn from(s: &str) -> Self {
        ByteArray::from_bytes(s.as_bytes())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn new() {
        assert_eq!(ByteArray::new().to_bytes(), [0]);
    }

    #[test]
    fn from_vec_bytes() {
        assert_eq!(ByteArray::from(&vec![]).to_bytes(), b"\x00");
        assert_eq!(
            ByteArray::from(&vec![10u8, 5u8, 4u8]).to_bytes(),
            [10, 5, 4]
        );
    }

    #[test]
    fn from_bytes() {
        //assert_eq!(ByteArray::from_bytes(&[]).to_bytes(), b"\x00");
        assert_eq!(
            ByteArray::from_bytes(&[10u8, 5u8, 4u8]).to_bytes(),
            [10, 5, 4]
        );
        assert_eq!(
            ByteArray::from_bytes(b"\x41\x42\x43").to_bytes(),
            [65, 66, 67]
        );
    }

    #[test]
    fn from_integer() {
        assert_eq!(
            ByteArray::try_from(&Integer::from(0u32))
                .unwrap()
                .to_bytes(),
            b"\x00"
        );
        assert_eq!(
            ByteArray::try_from(&Integer::from(3u32))
                .unwrap()
                .to_bytes(),
            b"\x03"
        );
        assert_eq!(
            ByteArray::try_from(&Integer::from(23591u32))
                .unwrap()
                .to_bytes(),
            b"\x5c\x27"
        );
        assert_eq!(
            ByteArray::try_from(&Integer::from(23592u32))
                .unwrap()
                .to_bytes(),
            b"\x5c\x28"
        );
        assert_eq!(
            ByteArray::try_from(&Integer::from(4294967295u64))
                .unwrap()
                .to_bytes(),
            b"\xff\xff\xff\xff"
        );
        assert_eq!(
            ByteArray::try_from(&Integer::from(4294967296u64))
                .unwrap()
                .to_bytes(),
            b"\x01\x00\x00\x00\x00"
        );
        assert!(ByteArray::try_from(&Integer::from(-2i64)).is_err());
    }

    #[test]
    fn from_string() {
        assert_eq!(ByteArray::from("ABC").to_bytes(), b"\x41\x42\x43");
        assert_eq!(ByteArray::from("Ä").to_bytes(), b"\xc3\x84");
        assert_eq!(ByteArray::from("1001").to_bytes(), b"\x31\x30\x30\x31");
        assert_eq!(ByteArray::from("1A").to_bytes(), b"\x31\x41");
    }

    #[test]
    fn test_extend() {
        let mut b = ByteArray::from_bytes(b"\x04\x03");
        b.extend(&ByteArray::from_bytes(b"\x10\x11\x12"));
        assert_eq!(b, ByteArray::from_bytes(b"\x04\x03\x10\x11\x12"))
    }

    #[test]
    fn test_append() {
        let b = ByteArray::from_bytes(b"\x04\x03");
        let res = b.new_append(&ByteArray::from_bytes(b"\x10\x11\x12"));
        assert_eq!(res, ByteArray::from_bytes(b"\x04\x03\x10\x11\x12"))
    }

    #[test]
    fn prepend_byte() {
        assert_eq!(
            ByteArray::from_bytes(b"\x03").new_prepend_byte(4u8),
            ByteArray::from_bytes(b"\x04\x03")
        )
    }

    #[test]
    fn to_integer() {
        assert_eq!(
            ByteArray::from_bytes(b"\x00").into_integer(),
            Integer::from(0u32)
        );
        assert_eq!(
            ByteArray::from_bytes(b"\x03").into_integer(),
            Integer::from(3u32)
        );
        assert_eq!(
            ByteArray::from_bytes(b"\x5c\x27").into_integer(),
            Integer::from(23591u32)
        );
        assert_eq!(
            ByteArray::from_bytes(b"\x5c\x28").into_integer(),
            Integer::from(23592u32)
        );
        assert_eq!(
            ByteArray::from_bytes(b"\xff\xff\xff\xff").into_integer(),
            Integer::from(4294967295u64)
        );
        assert_eq!(
            ByteArray::from_bytes(b"\x01\x00\x00\x00\x00").into_integer(),
            Integer::from(4294967296u64)
        );
    }

    #[test]
    fn cut_bit_length() {
        assert_eq!(
            ByteArray::base64_decode("/w==")
                .unwrap()
                .cut_bit_length(1)
                .unwrap(),
            ByteArray::base64_decode("AQ==").unwrap()
        );
        assert_eq!(
            ByteArray::base64_decode("Dw==")
                .unwrap()
                .cut_bit_length(2)
                .unwrap(),
            ByteArray::base64_decode("Aw==").unwrap()
        );
        assert_eq!(
            ByteArray::base64_decode("/w==")
                .unwrap()
                .cut_bit_length(8)
                .unwrap(),
            ByteArray::base64_decode("/w==").unwrap()
        );
        assert_eq!(
            ByteArray::base64_decode("vu8=")
                .unwrap()
                .cut_bit_length(7)
                .unwrap(),
            ByteArray::base64_decode("bw==").unwrap()
        );
        assert_eq!(
            ByteArray::base64_decode("wP/u")
                .unwrap()
                .cut_bit_length(13)
                .unwrap(),
            ByteArray::base64_decode("H+4=").unwrap()
        );
        assert_eq!(
            ByteArray::base64_decode("q80=")
                .unwrap()
                .cut_bit_length(9)
                .unwrap(),
            ByteArray::base64_decode("Ac0=").unwrap()
        );
        assert_eq!(
            ByteArray::from_bytes(b"10011").cut_bit_length(0).unwrap(),
            ByteArray::from_bytes(&[0])
        );
        assert!(ByteArray::from_bytes(b"\x11").cut_bit_length(9).is_err());
    }

    #[test]
    fn base16_encode() {
        assert_eq!(ByteArray::from_bytes(b"").base16_encode().unwrap(), "00");
        assert_eq!(
            ByteArray::from_bytes(b"\x41").base16_encode().unwrap(),
            "41"
        );
        assert_eq!(
            ByteArray::from_bytes(b"\x60").base16_encode().unwrap(),
            "60"
        );
        assert_eq!(
            ByteArray::from_bytes(b"\x00").base16_encode().unwrap(),
            "00"
        );
        assert_eq!(
            ByteArray::from_bytes(b"\x7f").base16_encode().unwrap(),
            "7F"
        );
        assert_eq!(
            ByteArray::from_bytes(b"\x80").base16_encode().unwrap(),
            "80"
        );
        assert_eq!(
            ByteArray::from_bytes(b"\xff").base16_encode().unwrap(),
            "FF"
        );
        assert_eq!(
            ByteArray::from_bytes(b"\x41\x00").base16_encode().unwrap(),
            "4100"
        );
        assert_eq!(
            ByteArray::from_bytes(b"\x01\x01\x01")
                .base16_encode()
                .unwrap(),
            "010101"
        );
        assert_eq!(
            ByteArray::from_bytes(b"\x7F\x00\xFE\x03")
                .base16_encode()
                .unwrap(),
            "7F00FE03"
        );
    }

    #[test]
    fn base16_decode() {
        assert_eq!(ByteArray::base16_decode("00").unwrap().to_bytes(), b"\x00");
        assert_eq!(ByteArray::base16_decode("41").unwrap().to_bytes(), b"\x41");
        assert_eq!(ByteArray::base16_decode("60").unwrap().to_bytes(), b"\x60");
        assert_eq!(ByteArray::base16_decode("7F").unwrap().to_bytes(), b"\x7F");
        assert_eq!(ByteArray::base16_decode("80").unwrap().to_bytes(), b"\x80");
        assert_eq!(ByteArray::base16_decode("FF").unwrap().to_bytes(), b"\xff");
        assert_eq!(
            ByteArray::base16_decode("4100").unwrap().to_bytes(),
            b"\x41\x00"
        );
        assert_eq!(
            ByteArray::base16_decode("010101").unwrap().to_bytes(),
            b"\x01\x01\x01"
        );
        assert_eq!(
            ByteArray::base16_decode("7F00FE03").unwrap().to_bytes(),
            b"\x7F\x00\xFE\x03"
        );
        assert!(ByteArray::base16_decode("234G").is_err())
    }

    #[test]
    fn base32_encode() {
        assert_eq!(
            ByteArray::from_bytes(b"").base32_encode().unwrap(),
            "AA======"
        );
        assert_eq!(
            ByteArray::from_bytes(b"\x41").base32_encode().unwrap(),
            "IE======"
        );
        assert_eq!(
            ByteArray::from_bytes(b"\x60").base32_encode().unwrap(),
            "MA======"
        );
        assert_eq!(
            ByteArray::from_bytes(b"\x00").base32_encode().unwrap(),
            "AA======"
        );
        assert_eq!(
            ByteArray::from_bytes(b"\x7f").base32_encode().unwrap(),
            "P4======"
        );
        assert_eq!(
            ByteArray::from_bytes(b"\x80").base32_encode().unwrap(),
            "QA======"
        );
        assert_eq!(
            ByteArray::from_bytes(b"\xff").base32_encode().unwrap(),
            "74======"
        );
        assert_eq!(
            ByteArray::from_bytes(b"\x41\x00").base32_encode().unwrap(),
            "IEAA===="
        );
        assert_eq!(
            ByteArray::from_bytes(b"\x01\x01\x01")
                .base32_encode()
                .unwrap(),
            "AEAQC==="
        );
        assert_eq!(
            ByteArray::from_bytes(b"\x7F\x00\xFE\x03")
                .base32_encode()
                .unwrap(),
            "P4AP4AY="
        );
    }

    #[test]
    fn base32_decode() {
        assert_eq!(
            ByteArray::base32_decode("AA======").unwrap().to_bytes(),
            b"\x00"
        );
        assert_eq!(
            ByteArray::base32_decode("IE======").unwrap().to_bytes(),
            b"\x41"
        );
        assert_eq!(
            ByteArray::base32_decode("MA======").unwrap().to_bytes(),
            b"\x60"
        );
        assert_eq!(
            ByteArray::base32_decode("P4======").unwrap().to_bytes(),
            b"\x7F"
        );
        assert_eq!(
            ByteArray::base32_decode("QA======").unwrap().to_bytes(),
            b"\x80"
        );
        assert_eq!(
            ByteArray::base32_decode("74======").unwrap().to_bytes(),
            b"\xff"
        );
        assert_eq!(
            ByteArray::base32_decode("IEAA====").unwrap().to_bytes(),
            b"\x41\x00"
        );
        assert_eq!(
            ByteArray::base32_decode("AEAQC===").unwrap().to_bytes(),
            b"\x01\x01\x01"
        );
        assert_eq!(
            ByteArray::base32_decode("P4AP4AY=").unwrap().to_bytes(),
            b"\x7F\x00\xFE\x03"
        );
        assert!(ByteArray::base32_decode("P4AP4AY").is_err())
    }

    #[test]
    fn base64_encode() {
        assert_eq!(ByteArray::from_bytes(b"").base64_encode().unwrap(), "AA==");
        assert_eq!(
            ByteArray::from_bytes(b"\x41").base64_encode().unwrap(),
            "QQ=="
        );
        assert_eq!(
            ByteArray::from_bytes(b"\x60").base64_encode().unwrap(),
            "YA=="
        );
        assert_eq!(
            ByteArray::from_bytes(b"\x00").base64_encode().unwrap(),
            "AA=="
        );
        assert_eq!(
            ByteArray::from_bytes(b"\x7f").base64_encode().unwrap(),
            "fw=="
        );
        assert_eq!(
            ByteArray::from_bytes(b"\x80").base64_encode().unwrap(),
            "gA=="
        );
        assert_eq!(
            ByteArray::from_bytes(b"\xff").base64_encode().unwrap(),
            "/w=="
        );
        assert_eq!(
            ByteArray::from_bytes(b"\x41\x00").base64_encode().unwrap(),
            "QQA="
        );
        assert_eq!(
            ByteArray::from_bytes(b"\x01\x01\x01")
                .base64_encode()
                .unwrap(),
            "AQEB"
        );
        assert_eq!(
            ByteArray::from_bytes(b"\x7F\x00\xFE\x03")
                .base64_encode()
                .unwrap(),
            "fwD+Aw=="
        );
    }

    #[test]
    fn base64_decode() {
        assert_eq!(
            ByteArray::base64_decode("AA==").unwrap().to_bytes(),
            b"\x00"
        );
        assert_eq!(
            ByteArray::base64_decode("QQ==").unwrap().to_bytes(),
            b"\x41"
        );
        assert_eq!(
            ByteArray::base64_decode("YA==").unwrap().to_bytes(),
            b"\x60"
        );
        assert_eq!(
            ByteArray::base64_decode("fw==").unwrap().to_bytes(),
            b"\x7F"
        );
        assert_eq!(
            ByteArray::base64_decode("gA==").unwrap().to_bytes(),
            b"\x80"
        );
        assert_eq!(
            ByteArray::base64_decode("/w==").unwrap().to_bytes(),
            b"\xff"
        );
        assert_eq!(
            ByteArray::base64_decode("QQA=").unwrap().to_bytes(),
            b"\x41\x00"
        );
        assert_eq!(
            ByteArray::base64_decode("AQEB").unwrap().to_bytes(),
            b"\x01\x01\x01"
        );
        assert_eq!(
            ByteArray::base64_decode("fwD+Aw==").unwrap().to_bytes(),
            b"\x7F\x00\xFE\x03"
        );
        assert!(ByteArray::base64_decode("fwD+Aw=").is_err())
    }
}
