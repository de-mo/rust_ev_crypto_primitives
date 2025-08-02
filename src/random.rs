// Copyright © 2024 Denis Morel

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

//! Module that implement random functions
//!
use crate::{
    alphabets::Alphabet,
    basic_crypto_functions::{random_bytes as basic_random_bytes, BasisCryptoError},
    integer::ToByteArrayError,
    ByteArray, ByteArrayError, ConstantsTrait, OperationsTrait, ToByteArryTrait,
};
use rug::Integer;
use thiserror::Error;

#[derive(Error, Debug)]
#[error(transparent)]
/// Error im Mod Exponentiate
pub struct RandomError(#[from] RandomErrorRepr);

#[derive(Error, Debug)]
enum RandomErrorRepr {
    #[error("Error generating random byte")]
    RandomByte { source: BasisCryptoError },
    #[error("Error to byte array in {location}")]
    ToByteArray {
        location: &'static str,
        source: ToByteArrayError,
    },
    #[error("Error with cut_bit_length in {location}")]
    CutToBitLength {
        location: &'static str,
        source: ByteArrayError,
    },
    #[error("Error calling random byte in gen_random_integer")]
    RandomByteInteger { source: Box<RandomError> },
    #[error("Upper bound cannot be 0")]
    UpperBoundZero,
    #[error("Error gen random integer in {location}")]
    GenInteger {
        location: &'static str,
        source: Box<RandomError>,
    },
}

/// Random bytes of give size
///
/// # Error
/// If an error appears creating the random bytes
pub fn random_bytes(size: usize) -> Result<ByteArray, RandomError> {
    basic_random_bytes(size)
        .map_err(|e| RandomErrorRepr::RandomByte { source: e })
        .map_err(RandomError::from)
}

/// Random integer with upper bound
///
/// # Error
/// If an error appears creating the random Integer
pub fn gen_random_integer(m: &Integer) -> Result<Integer, RandomError> {
    if m.is_zero() {
        return Err(RandomError::from(RandomErrorRepr::UpperBoundZero));
    }
    if m == Integer::one() {
        return Ok(Integer::zero().clone());
    }
    let length = m.byte_length().map_err(|e| RandomErrorRepr::ToByteArray {
        location: "GenRandomInteger",
        source: e,
    })?;
    let bit_length = m.nb_bits();
    loop {
        let r_bytes = random_bytes(length)
            .map_err(|e| RandomErrorRepr::RandomByteInteger {
                source: Box::new(e),
            })?
            .cut_bit_length(bit_length)
            .map_err(|e| RandomErrorRepr::CutToBitLength {
                location: "GenRandomInteger",
                source: e,
            })?;
        let r = r_bytes.into_integer();
        if &r < m {
            return Ok(r);
        }
    }
}

/// Random vector with upper bound `q` of size `n`
///
/// # Error
/// If an error appears creating the random vector
pub fn gen_random_vector(q: &Integer, n: usize) -> Result<Vec<Integer>, RandomError> {
    (0..n)
        .map(|_| gen_random_integer(q))
        .collect::<Result<_, _>>()
        .map_err(|e| RandomErrorRepr::GenInteger {
            location: "gen_random_vector",
            source: Box::new(e),
        })
        .map_err(RandomError::from)
}

/// Random string of length `l` with the given alphabet
///
/// # Error
/// If an error appears creating the random string
pub fn gen_random_string(l: usize, alphabet: &Alphabet) -> Result<String, RandomError> {
    let k = Integer::from(alphabet.size());
    (0..l)
        .map(|_| {
            gen_random_integer(&k).map(|m| {
                alphabet
                    .character_at_pos(m.to_u64_wrapping() as usize)
                    .unwrap()
            })
        })
        .collect::<Result<_, _>>()
        .map_err(|e| RandomErrorRepr::GenInteger {
            location: "gen_random_string",
            source: Box::new(e),
        })
        .map_err(RandomError::from)
}
