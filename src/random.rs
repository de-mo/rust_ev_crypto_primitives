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
    basic_crypto_functions::{random_bytes as basic_random_bytes, BasisCryptoError},
    ByteArray,
};

/// Random bytes of give size
///
/// # Error
/// If an error appears creating the random bytes
pub fn random_bytes(size: usize) -> Result<ByteArray, BasisCryptoError> {
    basic_random_bytes(size)
}
