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

//! Module to extend functionalities of the used big integer (`BigUint` or `Integer`)
//!
//! The extended functionalities are implemented using Trait that have to be
//! used in the client modules
//!

use crate::{ ByteArray, Decode, Encode };
use std::fmt::Debug;
use std::sync::OnceLock;
use thiserror::Error;

#[cfg(feature = "num-bigint")]
use num_bigint::{ BigInt, BigUint, Sign };
#[cfg(feature = "num-bigint")]
use num_traits::Num;

#[cfg(feature = "rug")]
use rug::Integer;

#[cfg(feature = "num-bigint")]
/// Type alias for all the crate
pub type MPInteger = BigUint;

#[cfg(feature = "rug")]
/// Type alias for all the crate
pub type MPInteger = Integer;

/// Trait to implement constant numbers
pub trait Constants {
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

/// Trait to extend operations of BigUInt
pub trait Operations: Sized {
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
    fn from_hexa_string(s: &str) -> Result<Self, MPIntegerError>;

    /// Generate the hexadecimal String
    fn to_hexa(&self) -> String;

    fn from_hexa_string_slice(vs: &[String]) -> Result<Vec<Self>, MPIntegerError> {
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
pub enum MPIntegerError {
    #[error("Integer must be positive or zero")]
    IsNegative,
    #[error("Error parsing {orig} in BigUInt in method {fnname}")] ParseError {
        orig: String,
        fnname: String,
    },
    #[error(
        "Error parsing {orig} in BigUInt in method {fnname} caused by {source}"
    )] ParseErrorWithSource {
        orig: String,
        fnname: String,
        #[cfg(feature = "num-bigint")]
        source: num_bigint::ParseBigIntError,
        #[cfg(feature = "rug")]
        source: rug::integer::ParseIntegerError,
    },
}

/// Trait to calculate byte length
pub trait ByteLength {
    /// Byte legnth of a BigUInt
    fn byte_length(&self) -> usize;
}

impl ByteLength for MPInteger {
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

static ZERO: OnceLock<MPInteger> = OnceLock::new();
static ONE: OnceLock<MPInteger> = OnceLock::new();
static TWO: OnceLock<MPInteger> = OnceLock::new();
static THREE: OnceLock<MPInteger> = OnceLock::new();
static FOR: OnceLock<MPInteger> = OnceLock::new();
static FIVE: OnceLock<MPInteger> = OnceLock::new();

impl Constants for MPInteger {
    fn zero() -> &'static Self {
        ZERO.get_or_init(|| MPInteger::from(0u8))
    }

    fn one() -> &'static Self {
        ONE.get_or_init(|| MPInteger::from(1u8))
    }

    fn two() -> &'static Self {
        TWO.get_or_init(|| MPInteger::from(2u8))
    }
    fn three() -> &'static Self {
        THREE.get_or_init(|| MPInteger::from(3u8))
    }
    fn four() -> &'static Self {
        FOR.get_or_init(|| MPInteger::from(4u8))
    }
    fn five() -> &'static Self {
        FIVE.get_or_init(|| MPInteger::from(5u8))
    }
}

#[cfg(feature = "num-bigint")]
impl Operations for BigUint {
    fn is_even(&self) -> bool {
        &(self % Self::two()) == Self::zero()
    }

    fn nb_bits(&self) -> usize {
        self.bits() as usize
    }

    fn mod_exponentiate(&self, exp: &Self, modulus: &Self) -> Self {
        self.modpow(exp, modulus)
    }

    fn mod_negate(&self, modulus: &Self) -> Self {
        let bi = BigInt::from_biguint(Sign::Minus, self.clone());
        let modulus_bi = BigInt::from_biguint(Sign::Plus, modulus.clone());
        let neg: BigInt = &bi % &modulus_bi;
        match neg.to_biguint() {
            Some(n) => n,
            None => (&neg + &modulus_bi).to_biguint().unwrap(),
        }
    }

    fn mod_multiply(&self, other: &Self, modulus: &Self) -> Self {
        (self * other) % modulus
    }

    fn mod_square(&self, modulus: &Self) -> Self {
        self.mod_multiply(self, modulus)
    }

    fn mod_inverse(&self, modulus: &Self) -> Self {
        self.mod_exponentiate(&(modulus - Self::two()), modulus)
    }
}

#[cfg(feature = "rug")]
impl Operations for Integer {
    fn is_even(&self) -> bool {
        self.is_even()
    }

    fn mod_exponentiate(&self, exp: &Self, modulus: &Self) -> Self {
        MPInteger::from(self.pow_mod_ref(exp, modulus).unwrap())
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
        self.mod_exponentiate(MPInteger::two(), modulus)
    }

    fn mod_inverse(&self, modulus: &Self) -> Self {
        let from = Integer::from(modulus - Self::two());
        self.mod_exponentiate(&from, modulus)
    }

    fn nb_bits(&self) -> usize {
        self.significant_bits() as usize
    }

    fn mod_add(&self, other: &Self, modulus: &Self) -> Self {
        let res = MPInteger::from(self + other);
        res.modulo(modulus)
    }

    fn mod_sub(&self, other: &Self, modulus: &Self) -> Self {
        self.mod_add(&MPInteger::from(-other), modulus)
    }
}

#[cfg(feature = "num-bigint")]
impl Hexa for BigUint {
    fn from_hexa_string(s: &str) -> Result<Self, MPIntegerError> {
        if !s.starts_with("0x") && !s.starts_with("0X") {
            return Err(MPIntegerError::ParseError {
                orig: s.to_string(),
                fnname: "from_hexa_string".to_string(),
            });
        }
        <BigUint>::from_str_radix(&s[2..], 16).map_err(|e| MPIntegerError::ParseErrorWithSource {
            orig: s.to_string(),
            fnname: "from_hexa_string".to_string(),
            source: e,
        })
    }

    fn to_hexa(&self) -> String {
        format!("{}{}", "0x", self.to_str_radix(16))
    }
}

#[cfg(feature = "rug")]
impl Hexa for Integer {
    fn from_hexa_string(s: &str) -> Result<Self, MPIntegerError> {
        if !s.starts_with("0x") && !s.starts_with("0X") {
            return Err(MPIntegerError::ParseError {
                orig: s.to_string(),
                fnname: "from_hexa_string".to_string(),
            });
        }
        Integer::parse_radix(&s[2..], 16)
            .map(Integer::from)
            .map_err(|e| MPIntegerError::ParseErrorWithSource {
                orig: s.to_string(),
                fnname: "from_hexa_string".to_string(),
                source: e,
            })
    }

    fn to_hexa(&self) -> String {
        format!("{}{}", "0x", self.to_string_radix(16))
    }
}

impl Decode for MPInteger {
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

impl Encode for MPInteger {
    type Error = MPIntegerError;
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
        assert_eq!(MPInteger::from(0u32).nb_bits(), 0);
        assert_eq!(MPInteger::from(1u32).nb_bits(), 1);
        assert_eq!(MPInteger::from(10u32).nb_bits(), 4);
    }

    #[test]
    fn byte_length() {
        assert_eq!(MPInteger::from(0u32).byte_length(), 0);
        assert_eq!(MPInteger::from(3u32).byte_length(), 1);
        assert_eq!(MPInteger::from(23591u32).byte_length(), 2);
        assert_eq!(MPInteger::from(23592u32).byte_length(), 2);
        assert_eq!(MPInteger::from(4294967295u64).byte_length(), 4);
        assert_eq!(MPInteger::from(4294967296u64).byte_length(), 5);
    }

    #[test]
    fn from_exa() {
        assert_eq!(MPInteger::from_hexa_string("0x0").unwrap(), MPInteger::from(0u32));
        assert_eq!(MPInteger::from_hexa_string("0xa").unwrap(), MPInteger::from(10u32));
        assert_eq!(MPInteger::from_hexa_string("0xab").unwrap(), MPInteger::from(171u32));
        assert_eq!(MPInteger::from_hexa_string("0x12D9E8").unwrap(), MPInteger::from(1235432u32));
        assert!(MPInteger::from_hexa_string("123").is_err());
        assert!(MPInteger::from_hexa_string("0xtt").is_err());
        assert_eq!(MPInteger::from_hexa_string("0x12D9E8").unwrap(), MPInteger::from(1235432u32));
    }

    #[test]
    fn from_exa_string_slice() {
        assert_eq!(
            MPInteger::from_hexa_string_slice(&["0x0".to_string(), "0xa".to_string()]).unwrap(),
            vec![MPInteger::from(0u32), MPInteger::from(10u32)]
        );
        assert!(
            MPInteger::from_hexa_string_slice(&["123".to_string(), "0xa".to_string()]).is_err()
        );
    }

    #[test]
    fn to_exa() {
        assert_eq!(MPInteger::from(0u32).to_hexa(), "0x0");
        assert_eq!(MPInteger::from(10u32).to_hexa(), "0xa");
        assert_eq!(MPInteger::from(171u32).to_hexa(), "0xab");
        assert_eq!(MPInteger::from(1235432u32).to_hexa(), "0x12d9e8");
    }

    #[test]
    fn test_is_even_odd() {
        assert!(MPInteger::from(0u8).is_even());
        assert!(MPInteger::from(2u8).is_even());
        assert!(!MPInteger::from(3u8).is_even());
        assert!(!MPInteger::from(0u8).is_odd());
        assert!(!MPInteger::from(2u8).is_odd());
        assert!(MPInteger::from(3u8).is_odd());
    }

    #[test]
    fn test_mod_multiply() {
        assert_eq!(
            MPInteger::from(426u32).mod_multiply(
                &MPInteger::from(964u32),
                &MPInteger::from(235u32)
            ),
            MPInteger::from(119u32)
        );
        let a = MPInteger::from(10123465234878998usize);
        let b = MPInteger::from(65746311545646431usize);
        let m = MPInteger::from(10005412336548794usize);
        let res = MPInteger::from(4652135769797794usize);
        assert_eq!(a.mod_multiply(&b, &m), res)
    }

    #[test]
    fn test_mod_negate() {
        assert_eq!(
            MPInteger::from(12u8).mod_negate(&MPInteger::from(10u32)),
            MPInteger::from(8u32)
        );
    }

    #[test]
    fn test_mod_add() {
        let modulo = MPInteger::from(7u8);
        assert_eq!(
            MPInteger::from(5u8).mod_add(&MPInteger::from(3u8), &modulo),
            MPInteger::from(1u32)
        );
        assert_eq!(
            MPInteger::from(5u8).mod_add(&MPInteger::from(-7i8), &modulo),
            MPInteger::from(5u32)
        );
        assert_eq!(
            MPInteger::from(5u8).mod_add(&MPInteger::from(-14i8), &modulo),
            MPInteger::from(5u32)
        );
        assert_eq!(
            MPInteger::from(-2i8).mod_add(&MPInteger::from(20i8), &modulo),
            MPInteger::from(4u32)
        );
    }

    #[test]
    fn test_mod_sub() {
        let modulo = MPInteger::from(7u8);
        assert_eq!(
            MPInteger::from(5u8).mod_sub(&MPInteger::from(3u8), &modulo),
            MPInteger::from(2u32)
        );
        assert_eq!(
            MPInteger::from(5u8).mod_sub(&MPInteger::from(-6i8), &modulo),
            MPInteger::from(4u32)
        );
        assert_eq!(
            MPInteger::from(5u8).mod_sub(&MPInteger::from(-15i8), &modulo),
            MPInteger::from(6u32)
        );
        assert_eq!(
            MPInteger::from(-2i8).mod_sub(&MPInteger::from(20i8), &modulo),
            MPInteger::from(6u32)
        );
    }

    #[test]
    fn test_mod_inverse() {
        assert_eq!(
            MPInteger::from(3u16).mod_inverse(&MPInteger::from(11u16)),
            MPInteger::from(4u16)
        );
        assert_eq!(
            MPInteger::from(10u16).mod_inverse(&MPInteger::from(17u16)),
            MPInteger::from(12u16)
        );
    }

    #[test]
    fn base16_encode() {
        assert_eq!(MPInteger::from(0u8).base16_encode().unwrap(), "00");
        assert_eq!(MPInteger::from(10u8).base16_encode().unwrap(), "0A");
        assert!(MPInteger::from(-2i64).base16_encode().is_err());
    }

    #[test]
    fn base16_decode() {
        assert_eq!(MPInteger::base16_decode("00").unwrap(), MPInteger::from(0u8));
        assert_eq!(MPInteger::base16_decode("A1").unwrap(), MPInteger::from(161u8));
    }

    #[test]
    fn base32_encode() {
        assert_eq!(MPInteger::from(0u8).base32_encode().unwrap(), "AA======");
        assert_eq!(MPInteger::from(10u8).base32_encode().unwrap(), "BI======");
        assert!(MPInteger::from(-2i64).base32_encode().is_err());
    }

    #[test]
    fn base32_decode() {
        assert_eq!(MPInteger::base32_decode("AA======").unwrap(), MPInteger::from(0u8));
        assert_eq!(MPInteger::base32_decode("BI======").unwrap(), MPInteger::from(10u8));
    }

    #[test]
    fn base64_encode() {
        assert_eq!(MPInteger::from(0u8).base64_encode().unwrap(), "AA==");
        assert_eq!(MPInteger::from(10u8).base64_encode().unwrap(), "Cg==");
        assert!(MPInteger::from(-2i64).base64_encode().is_err());
    }

    #[test]
    fn base64_decode() {
        assert_eq!(MPInteger::base64_decode("AA==").unwrap(), MPInteger::from(0u8));
        assert_eq!(MPInteger::base64_decode("Cg==").unwrap(), MPInteger::from(10u8));
    }
}
