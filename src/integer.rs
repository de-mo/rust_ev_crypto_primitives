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

//! Module to extend functionalities of the used big `Integer`.
//!
//! The extended functionalities are implemented using Trait that have to be
//! used in the client modules
//!

use crate::{ByteArray, DecodeTrait, EncodeTrait};
use rug::Integer;
use std::fmt::Debug;
use std::sync::OnceLock;
use thiserror::Error;

/// Trait to implement constant numbers
pub trait ConstantsTrait: Sized {
    /// Zero
    fn zero() -> &'static Self;
    /// One
    fn one() -> &'static Self;
    /// Two
    fn two() -> &'static Self;
    /// Three
    fn three() -> &'static Self;
    /// Four
    fn four() -> &'static Self;
    /// Five
    fn five() -> &'static Self;
}

/// Trait to extend operations of [Integer]
pub trait OperationsTrait: Sized {
    /// Test if is even
    fn is_even(&self) -> bool;

    /// Test if is odd
    fn is_odd(&self) -> bool {
        !self.is_even()
    }

    /// Returns the number of bits representing the number
    fn nb_bits(&self) -> usize;

    /// Calculate the add modulo: self + other % modulus
    fn mod_add(&self, other: &Self, modulus: &Self) -> Self;

    /// Calculate the substraction modulo: self - other % modulus
    fn mod_sub(&self, other: &Self, modulus: &Self) -> Self;

    /// Calculate the exponentiate modulo: self^exp % modulus
    fn mod_exponentiate(&self, exp: &Self, modulus: &Self) -> Self;

    /// Calculate the negative number modulo modulus (is a positive number): -self & modulus
    fn mod_negate(&self, modulus: &Self) -> Self;

    /// Calculate the exponentiate modulo: self*other % modulus
    fn mod_multiply(&self, other: &Self, modulus: &Self) -> Self;

    /// multiply all elements of other with self (scalar product)
    fn mod_scalar_multiply(&self, others: &[Self], modulus: &Self) -> Vec<Self> {
        others
            .iter()
            .map(|other| self.mod_multiply(other, modulus))
            .collect()
    }

    /// Calculate the multiplication modulo: self*other % modulus
    fn mod_square(&self, modulus: &Self) -> Self {
        self.mod_multiply(self, modulus)
    }

    /// Calculate the inverse modulo: self^(-1) % modulus
    ///
    /// Return the correct answer only if modulus is prime
    fn mod_inverse(&self, modulus: &Self) -> Self;

    fn mod_divide(&self, divisor: &Self, modulus: &Self) -> Self {
        self.mod_multiply(&divisor.mod_inverse(modulus), modulus)
    }
}

/// Transformation from or to String in hexadecimal according to the specifications
pub trait Hexa: Sized {
    /// Create object from hexadecimal String. If not valid return an error
    fn from_hexa_string(s: &str) -> Result<Self, IntegerError>;

    /// Generate the hexadecimal String
    fn to_hexa(&self) -> String;

    fn from_hexa_string_slice(vs: &[String]) -> Result<Vec<Self>, IntegerError> {
        let mut decoded = vs.iter().map(|s| Self::from_hexa_string(s.as_str()));
        let decoded_2 = decoded.clone();
        match decoded.find(|e| e.is_err()) {
            Some(e) => Err(e.err().unwrap()),
            None => Ok(decoded_2.map(|e| e.unwrap()).collect()),
        }
    }
}

// enum representing the errors with big integer
#[derive(Error, Debug)]
pub enum IntegerError {
    #[error("Integer must be positive or zero")]
    IsNegative,
    #[error("Error parsing {orig} in Integer in method {fnname}")]
    ParseError { orig: String, fnname: String },
    #[error("Error parsing {orig} in Integer in method {fnname} caused by {source}")]
    ParseErrorWithSource {
        orig: String,
        fnname: String,
        source: rug::integer::ParseIntegerError,
    },
}

/// Trait to calculate byte length
pub trait ByteLengthTrait {
    /// Byte legnth of an object
    fn byte_length(&self) -> usize;
}

impl ByteLengthTrait for Integer {
    fn byte_length(&self) -> usize {
        let bits = self.nb_bits();
        let bytes = bits / 8;
        if bits % 8 == 0 {
            bytes
        } else {
            bytes + 1
        }
    }
}

static ZERO: OnceLock<Integer> = OnceLock::new();
static ONE: OnceLock<Integer> = OnceLock::new();
static TWO: OnceLock<Integer> = OnceLock::new();
static THREE: OnceLock<Integer> = OnceLock::new();
static FOR: OnceLock<Integer> = OnceLock::new();
static FIVE: OnceLock<Integer> = OnceLock::new();

impl ConstantsTrait for Integer {
    fn zero() -> &'static Self {
        ZERO.get_or_init(|| Integer::from(0u8))
    }

    fn one() -> &'static Self {
        ONE.get_or_init(|| Integer::from(1u8))
    }

    fn two() -> &'static Self {
        TWO.get_or_init(|| Integer::from(2u8))
    }
    fn three() -> &'static Self {
        THREE.get_or_init(|| Integer::from(3u8))
    }
    fn four() -> &'static Self {
        FOR.get_or_init(|| Integer::from(4u8))
    }
    fn five() -> &'static Self {
        FIVE.get_or_init(|| Integer::from(5u8))
    }
}

impl OperationsTrait for Integer {
    fn is_even(&self) -> bool {
        self.is_even()
    }

    fn mod_exponentiate(&self, exp: &Self, modulus: &Self) -> Self {
        Integer::from(self.pow_mod_ref(exp, modulus).unwrap())
    }

    fn mod_negate(&self, modulus: &Self) -> Self {
        let bi = Integer::from(-self);
        let modulus_bi = Integer::from(-modulus);
        let mut neg = bi % &modulus_bi;
        if neg < 0 {
            neg += &modulus_bi.abs();
        }
        neg
    }

    fn mod_multiply(&self, other: &Self, modulus: &Self) -> Self {
        Integer::from(self * other) % modulus
    }

    fn mod_square(&self, modulus: &Self) -> Self {
        self.mod_exponentiate(Integer::two(), modulus)
    }

    fn mod_inverse(&self, modulus: &Self) -> Self {
        let from = Integer::from(modulus - Self::two());
        self.mod_exponentiate(&from, modulus)
    }

    fn nb_bits(&self) -> usize {
        self.significant_bits() as usize
    }

    fn mod_add(&self, other: &Self, modulus: &Self) -> Self {
        let res = Integer::from(self + other);
        res.modulo(modulus)
    }

    fn mod_sub(&self, other: &Self, modulus: &Self) -> Self {
        self.mod_add(&Integer::from(-other), modulus)
    }
}

impl Hexa for Integer {
    fn from_hexa_string(s: &str) -> Result<Self, IntegerError> {
        if !s.starts_with("0x") && !s.starts_with("0X") {
            return Err(IntegerError::ParseError {
                orig: s.to_string(),
                fnname: "from_hexa_string".to_string(),
            });
        }
        Integer::parse_radix(&s[2..], 16)
            .map(Integer::from)
            .map_err(|e| IntegerError::ParseErrorWithSource {
                orig: s.to_string(),
                fnname: "from_hexa_string".to_string(),
                source: e,
            })
    }

    fn to_hexa(&self) -> String {
        format!("{}{}", "0x", self.to_string_radix(16))
    }
}

impl DecodeTrait for Integer {
    fn base16_decode(s: &str) -> Result<Self, crate::byte_array::ByteArrayError> {
        ByteArray::base16_decode(s).map(|b| b.into_mp_integer())
    }

    fn base32_decode(s: &str) -> Result<Self, crate::byte_array::ByteArrayError> {
        ByteArray::base32_decode(s).map(|b| b.into_mp_integer())
    }

    fn base64_decode(s: &str) -> Result<Self, crate::byte_array::ByteArrayError> {
        ByteArray::base64_decode(s).map(|b| b.into_mp_integer())
    }
}

impl EncodeTrait for Integer {
    type Error = IntegerError;
    fn base16_encode(&self) -> Result<String, Self::Error> {
        Ok(ByteArray::try_from(self)?.base16_encode().unwrap())
    }

    fn base32_encode(&self) -> Result<String, Self::Error> {
        Ok(ByteArray::try_from(self)?.base32_encode().unwrap())
    }

    fn base64_encode(&self) -> Result<String, Self::Error> {
        Ok(ByteArray::try_from(self)?.base64_encode().unwrap())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn bit_length() {
        assert_eq!(Integer::from(0u32).nb_bits(), 0);
        assert_eq!(Integer::from(1u32).nb_bits(), 1);
        assert_eq!(Integer::from(10u32).nb_bits(), 4);
    }

    #[test]
    fn byte_length() {
        assert_eq!(Integer::from(0u32).byte_length(), 0);
        assert_eq!(Integer::from(3u32).byte_length(), 1);
        assert_eq!(Integer::from(23591u32).byte_length(), 2);
        assert_eq!(Integer::from(23592u32).byte_length(), 2);
        assert_eq!(Integer::from(4294967295u64).byte_length(), 4);
        assert_eq!(Integer::from(4294967296u64).byte_length(), 5);
    }

    #[test]
    fn from_exa() {
        assert_eq!(
            Integer::from_hexa_string("0x0").unwrap(),
            Integer::from(0u32)
        );
        assert_eq!(
            Integer::from_hexa_string("0xa").unwrap(),
            Integer::from(10u32)
        );
        assert_eq!(
            Integer::from_hexa_string("0xab").unwrap(),
            Integer::from(171u32)
        );
        assert_eq!(
            Integer::from_hexa_string("0x12D9E8").unwrap(),
            Integer::from(1235432u32)
        );
        assert!(Integer::from_hexa_string("123").is_err());
        assert!(Integer::from_hexa_string("0xtt").is_err());
        assert_eq!(
            Integer::from_hexa_string("0x12D9E8").unwrap(),
            Integer::from(1235432u32)
        );
    }

    #[test]
    fn from_exa_string_slice() {
        assert_eq!(
            Integer::from_hexa_string_slice(&["0x0".to_string(), "0xa".to_string()]).unwrap(),
            vec![Integer::from(0u32), Integer::from(10u32)]
        );
        assert!(Integer::from_hexa_string_slice(&["123".to_string(), "0xa".to_string()]).is_err());
    }

    #[test]
    fn to_exa() {
        assert_eq!(Integer::from(0u32).to_hexa(), "0x0");
        assert_eq!(Integer::from(10u32).to_hexa(), "0xa");
        assert_eq!(Integer::from(171u32).to_hexa(), "0xab");
        assert_eq!(Integer::from(1235432u32).to_hexa(), "0x12d9e8");
    }

    #[test]
    fn test_is_even_odd() {
        assert!(Integer::from(0u8).is_even());
        assert!(Integer::from(2u8).is_even());
        assert!(!Integer::from(3u8).is_even());
        assert!(!Integer::from(0u8).is_odd());
        assert!(!Integer::from(2u8).is_odd());
        assert!(Integer::from(3u8).is_odd());
    }

    #[test]
    fn test_mod_multiply() {
        assert_eq!(
            Integer::from(426u32).mod_multiply(&Integer::from(964u32), &Integer::from(235u32)),
            Integer::from(119u32)
        );
        let a = Integer::from(10123465234878998usize);
        let b = Integer::from(65746311545646431usize);
        let m = Integer::from(10005412336548794usize);
        let res = Integer::from(4652135769797794usize);
        assert_eq!(a.mod_multiply(&b, &m), res)
    }

    #[test]
    fn test_mod_negate() {
        assert_eq!(
            Integer::from(12u8).mod_negate(&Integer::from(10u32)),
            Integer::from(8u32)
        );
    }

    #[test]
    fn test_mod_add() {
        let modulo = Integer::from(7u8);
        assert_eq!(
            Integer::from(5u8).mod_add(&Integer::from(3u8), &modulo),
            Integer::from(1u32)
        );
        assert_eq!(
            Integer::from(5u8).mod_add(&Integer::from(-7i8), &modulo),
            Integer::from(5u32)
        );
        assert_eq!(
            Integer::from(5u8).mod_add(&Integer::from(-14i8), &modulo),
            Integer::from(5u32)
        );
        assert_eq!(
            Integer::from(-2i8).mod_add(&Integer::from(20i8), &modulo),
            Integer::from(4u32)
        );
    }

    #[test]
    fn test_mod_sub() {
        let modulo = Integer::from(7u8);
        assert_eq!(
            Integer::from(5u8).mod_sub(&Integer::from(3u8), &modulo),
            Integer::from(2u32)
        );
        assert_eq!(
            Integer::from(5u8).mod_sub(&Integer::from(-6i8), &modulo),
            Integer::from(4u32)
        );
        assert_eq!(
            Integer::from(5u8).mod_sub(&Integer::from(-15i8), &modulo),
            Integer::from(6u32)
        );
        assert_eq!(
            Integer::from(-2i8).mod_sub(&Integer::from(20i8), &modulo),
            Integer::from(6u32)
        );
    }

    #[test]
    fn test_mod_inverse() {
        assert_eq!(
            Integer::from(3u16).mod_inverse(&Integer::from(11u16)),
            Integer::from(4u16)
        );
        assert_eq!(
            Integer::from(10u16).mod_inverse(&Integer::from(17u16)),
            Integer::from(12u16)
        );
    }

    #[test]
    fn base16_encode() {
        assert_eq!(Integer::from(0u8).base16_encode().unwrap(), "00");
        assert_eq!(Integer::from(10u8).base16_encode().unwrap(), "0A");
        assert!(Integer::from(-2i64).base16_encode().is_err());
    }

    #[test]
    fn base16_decode() {
        assert_eq!(Integer::base16_decode("00").unwrap(), Integer::from(0u8));
        assert_eq!(Integer::base16_decode("A1").unwrap(), Integer::from(161u8));
    }

    #[test]
    fn base32_encode() {
        assert_eq!(Integer::from(0u8).base32_encode().unwrap(), "AA======");
        assert_eq!(Integer::from(10u8).base32_encode().unwrap(), "BI======");
        assert!(Integer::from(-2i64).base32_encode().is_err());
    }

    #[test]
    fn base32_decode() {
        assert_eq!(
            Integer::base32_decode("AA======").unwrap(),
            Integer::from(0u8)
        );
        assert_eq!(
            Integer::base32_decode("BI======").unwrap(),
            Integer::from(10u8)
        );
    }

    #[test]
    fn base64_encode() {
        assert_eq!(Integer::from(0u8).base64_encode().unwrap(), "AA==");
        assert_eq!(Integer::from(10u8).base64_encode().unwrap(), "Cg==");
        assert!(Integer::from(-2i64).base64_encode().is_err());
    }

    #[test]
    fn base64_decode() {
        assert_eq!(Integer::base64_decode("AA==").unwrap(), Integer::from(0u8));
        assert_eq!(Integer::base64_decode("Cg==").unwrap(), Integer::from(10u8));
    }
}
