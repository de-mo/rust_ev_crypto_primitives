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

use super::{BasisCryptoError, BasisCryptoErrorRepr};
use crate::ByteArray;
use openssl::rand::rand_bytes;

/// Random bytes of the given size
pub fn random_bytes(size: usize) -> Result<ByteArray, BasisCryptoError> {
    let mut buf = vec![0u8; size];
    rand_bytes(&mut buf).map_err(|e| BasisCryptoErrorRepr::RandomError { source: e })?;
    Ok(ByteArray::from_bytes(&buf))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_size() {
        assert_eq!(random_bytes(32).unwrap().len(), 32);
        assert_eq!(random_bytes(16).unwrap().len(), 16);
    }
}
