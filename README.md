# E-Voting Crypto Primitives in Rust

## Introduction

This crate implements functionalities of the crpyto primitives for the E-Voting system of Swiss Post. It is based on the specifications of Swiss Post, according to the following document version:

- [Crypo-primitives](https://gitlab.com/swisspost-evoting/crypto-primitives/crypto-primitives), version 1.4.1

It implements only the functionalities that are necessary for the implementation of the Verifier.

See [API Documentation](https://docs.rs/rust_ev_crypto_primitives/) for details

## Development guide

The crate is tested with the version of Rust defined in [Cargo.toml](Cargo.toml).

## Installation

The crate uses the crate [openssl](https://docs.rs/openssl/latest/openssl/) to wrap the functions of the library openssl for the basic cryptographic functions. Please check the installation guide of the crate.

The crate uses the crate [rug](https://crates.io/crates/rug) to wrap the functions of the library GMP for the performant big integers. Please check the installation guide of the crate.

## Licence

Rug is free software: you can redistribute it and/or modify it under the terms 
of the GNU Lesser General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version. See the full text of the [GNU LGPL](LICENSE.md) for details.

## Third party

See [THIRD_PARTY](THIRD_PARTY)
