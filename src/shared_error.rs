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

//! Definition of some shared error types

use thiserror::Error;

#[derive(Error, Debug)]
#[error("The value is not positive")]
/// Error if the value is not positive
pub struct NotPositiveError {}

#[derive(Error, Debug)]
#[error("The value {val} is negative")]
/// Error if the value is not positive
pub struct IsNegativeError {
    pub(crate) val: String,
}

#[derive(Error, Debug)]
#[error("The value {val} is not odd")]
/// Error if the value is not odd
pub struct NotOddError {
    pub(crate) val: String,
}

#[derive(Error, Debug)]
#[error("The fn {function} is not implemented")]
/// Error if the value is not odd
pub struct NotImplemented {
    pub(crate) function: &'static str,
}
