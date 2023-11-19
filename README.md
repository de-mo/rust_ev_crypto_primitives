# E-Voting Crypto Primitives in Rust

## Introduction

This crate implements functionalities of the crpyto primitives for the E-Voting system of Swiss Post. It is based on the specifications of Swiss Post, according to the following document version:

- [Crypo-primitives](https://gitlab.com/swisspost-evoting/crypto-primitives/crypto-primitives), version 1.3.0

## Development guide

The crate is tested with the version 1.74.0 of rust.

The crate uses the crate openssl to wrap the functions of the library openssl. Please check the installation guide of the create.

Generate the doc to see the documentation of the modules:

```shell
cargo doc
```

## Licence

Open source License Apache 2.0

See [LICENSE](LICENSE)

## Third party

See [THIRD_PARTY](THIRD_PARTY)
