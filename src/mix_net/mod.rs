// Copyright © 2023 Denis Morel
//
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
// <https://www.gnu.org/licenses/>

//! Module implementing the algorithm for the the mixnet

mod arguments;
mod commitments;
mod matrix;
mod shuffle;

pub use arguments::{
    HadamardArgument, MultiExponentiationArgument, ProductArgument, ShuffleArgument,
    SingleValueProductArgument, ZeroArgument,
};
use arguments::{
    HadamardArgumentError, MultiExponentiationArgumentError, ProductArgumentError,
    ShuffleArgumentError, SingleValueProductArgumentError, ZeroArgumentError,
};
use shuffle::ShuffleError;
pub use shuffle::{verify_shuffle, VerifyShuffleResult};
use thiserror::Error;

pub trait MixNetResultTrait: std::fmt::Display {
    fn is_ok(&self) -> bool;
}

#[derive(Error, Debug)]
#[error(transparent)]
pub struct MixnetError {
    source: Box<MixnetErrorRepr>,
}

#[derive(Error, Debug)]
enum MixnetErrorRepr {
    #[error("verify_shuffle error")]
    Shuffle(#[from] ShuffleError),
    #[error("Hadamard argument error")]
    HadamardArgument(#[from] HadamardArgumentError),
    #[error("Multiexponentiation argument error")]
    MultiExponentiationArgument(#[from] MultiExponentiationArgumentError),
    #[error("Product argument error")]
    ProductArgument(#[from] ProductArgumentError),
    #[error("Shuffle argument error")]
    ShuffleArgument(#[from] ShuffleArgumentError),
    #[error("Single value product argument error")]
    SingleValueProductArgument(#[from] SingleValueProductArgumentError),
    #[error("Zero argument error")]
    ZeroArgument(#[from] ZeroArgumentError),
}
