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

use thiserror::Error;

use crate::{integer::MPInteger, Constants};

pub struct Matrix(Vec<Vec<MPInteger>>);

#[derive(Error, Debug)]
pub enum MatrixError {
    #[error("The size {0} of the vector must the product of m={1} et n={2}")]
    WrongVectorSize(usize, usize, usize),
    #[error("The Matrix is malformed")]
    MalformedMatrix,
}

impl Matrix {
    pub fn get_matrix_dimensions(upper_n: usize) -> (usize, usize) {
        let mut m = 1;
        let mut n = upper_n;
        let mut i = (upper_n as f64).sqrt() as usize;
        while i > 1 {
            if upper_n % i == 0 {
                m = i;
                n = upper_n / i;
                return (m, n);
            }
            i -= 1;
        }
        (m, n)
    }

    fn new(m: usize, n: usize) -> Self {
        let v = vec![MPInteger::one().clone(); n];
        Self(vec![v.clone(); m])
    }

    pub fn to_matrix(v: &[MPInteger], (m, n): (usize, usize)) -> Result<Self, MatrixError> {
        if v.len() != m * n {
            return Err(MatrixError::WrongVectorSize(v.len(), m, n));
        }
        let mut res = Self::new(m, n);
        for i in 1..m {
            for j in 1..n {
                res.set_elt(&v[n * i + j], i, j)
            }
        }
        Ok(res)
    }

    pub fn transpose(&self) -> Result<Self, MatrixError> {
        if self.is_malformed() {
            return Err(MatrixError::MalformedMatrix);
        }
        let m = self.nb_rows();
        let n = self.nb_columns();
        let mut res = Self::new(n, m);
        for i in 1..m {
            for j in 1..n {
                res.set_elt(self.elt(i, j), j, i)
            }
        }
        Ok(res)
    }

    pub fn elt(&self, i: usize, j: usize) -> &MPInteger {
        &self.0[j][i]
    }

    pub fn set_elt(&mut self, value: &MPInteger, i: usize, j: usize) {
        self.0[j][i].clone_from(value)
    }

    pub fn nb_rows(&self) -> usize {
        self.0[0].len()
    }

    pub fn nb_columns(&self) -> usize {
        self.0.len()
    }

    pub fn column(&self, j: usize) -> &[MPInteger] {
        &self.0[j]
    }

    pub fn is_malformed(&self) -> bool {
        let expected = self.nb_rows();
        for c in self.0.iter() {
            if c.len() != expected {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_get_matrix_dimensions() {
        assert_eq!(Matrix::get_matrix_dimensions(12), (3, 4));
        assert_eq!(Matrix::get_matrix_dimensions(18), (3, 6));
        assert_eq!(Matrix::get_matrix_dimensions(23), (1, 23));
    }
}
