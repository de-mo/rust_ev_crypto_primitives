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

use crate::{integer::MPInteger, Ciphertext, HashableMessage};

#[derive(Debug, Clone)]
pub struct Matrix<T>
where
    T: Clone + Default + std::fmt::Debug,
{
    rows: Vec<Vec<T>>,
}

#[derive(Error, Debug)]
pub enum MatrixError {
    #[error("The size {0} of the vector must the product of m={1} et n={2}")]
    WrongVectorSize(usize, usize, usize),
    #[error("The Matrix is malformed")]
    MalformedMatrix,
    #[error("The Matrices have different size")]
    NotSameSize,
}

impl<T: Clone + Default + std::fmt::Debug> Matrix<T> {
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
        Self {
            rows: vec![vec![T::default(); n]; m],
        }
    }

    pub fn to_matrix(v: &[T], (m, n): (usize, usize)) -> Result<Self, MatrixError> {
        if v.len() != m * n {
            return Err(MatrixError::WrongVectorSize(v.len(), m, n));
        }
        let mut res = Self::new(m, n);
        for i in 0..m {
            for j in 0..n {
                res.set_elt(&v[i * n + j], i, j);
            }
        }
        Ok(res)
    }

    pub fn from_rows(rows: &[Vec<T>]) -> Result<Self, MatrixError> {
        let res = Self {
            rows: rows.to_vec(),
        };
        match res.is_malformed() {
            true => Err(MatrixError::MalformedMatrix),
            false => Ok(res),
        }
    }

    pub fn transpose(&self) -> Result<Self, MatrixError> {
        if self.is_malformed() {
            return Err(MatrixError::MalformedMatrix);
        }
        let m = self.nb_rows();
        let n = self.nb_columns();
        let mut res = Self::new(n, m);
        for i in 0..m {
            for j in 0..n {
                res.set_elt(self.elt(i, j), j, i);
            }
        }
        Ok(res)
    }

    pub fn elt(&self, i: usize, j: usize) -> &T {
        &self.rows[i][j]
    }

    pub fn elt_mut(&mut self, i: usize, j: usize) -> &mut T {
        &mut self.rows[i][j]
    }

    pub fn set_elt(&mut self, value: &T, i: usize, j: usize) {
        self.elt_mut(i, j).clone_from(value)
    }

    pub fn nb_rows(&self) -> usize {
        self.rows.len()
    }

    pub fn nb_columns(&self) -> usize {
        self.rows[0].len()
    }

    pub fn columns_iter(&self) -> impl Iterator<Item = Vec<&T>> + '_ {
        ColIter {
            matrix: self,
            index: 0,
        }
    }

    pub fn columns_cloned_iter(&self) -> impl Iterator<Item = Vec<T>> + '_ {
        self.columns_iter()
            .map(|e| e.into_iter().cloned().collect::<Vec<T>>())
    }

    pub fn rows_iter(&self) -> impl Iterator<Item = &Vec<T>> + '_ {
        self.rows.iter()
    }

    pub fn rows_cloned_iter(&self) -> impl Iterator<Item = Vec<T>> + '_ {
        self.rows_iter().map(|e| e.to_vec())
    }

    pub fn column(&self, j: usize) -> Vec<&T> {
        self.rows_iter().map(|r| &r[j]).collect()
    }

    pub fn row(&self, i: usize) -> Vec<&T> {
        self.rows[i].iter().collect::<Vec<_>>()
    }

    #[allow(dead_code)]
    pub fn row_cloned(&self, i: usize) -> Vec<T> {
        self.row(i).into_iter().cloned().collect()
    }

    #[allow(dead_code)]
    pub fn column_cloned(&self, i: usize) -> Vec<T> {
        self.column(i).into_iter().cloned().collect()
    }

    pub fn is_malformed(&self) -> bool {
        if self.rows.is_empty() {
            return false;
        }
        let size = self.rows[0].len();
        !self.rows_iter().all(|r| r.len() == size)
    }
}

impl Matrix<MPInteger> {
    #[allow(dead_code)]
    pub fn entrywise_product(&self, other: &Self) -> Result<Self, MatrixError> {
        if self.nb_rows() != other.nb_rows() || self.nb_columns() != other.nb_columns() {
            return Err(MatrixError::NotSameSize);
        }
        let mut res = Self::new(self.nb_rows(), self.nb_columns());
        for i in 1..self.nb_rows() {
            for j in 1..self.nb_columns() {
                res.set_elt(&MPInteger::from(self.elt(i, j) * other.elt(i, j)), j, i);
            }
        }
        Ok(res)
    }
}

impl<'a> From<&'a Matrix<Ciphertext>> for HashableMessage<'a> {
    fn from(value: &'a Matrix<Ciphertext>) -> Self {
        HashableMessage::from(
            value
                .rows_iter()
                .map(HashableMessage::from)
                .collect::<Vec<_>>(),
        )
    }
}

/*
impl<T> IntoIterator for Matrix<T> where T: Clone + Default + std::fmt::Debug {
    type Item = T;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
    }
}*/

struct ColIter<'a, T>
where
    T: Clone + Default + std::fmt::Debug,
{
    matrix: &'a Matrix<T>,
    index: usize,
}

impl<'a, T> Iterator for ColIter<'a, T>
where
    T: Clone + Default + std::fmt::Debug,
{
    type Item = Vec<&'a T>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.matrix.nb_columns() {
            let i = self.index;
            self.index += 1;
            return Some(self.matrix.column(i));
        }
        None
    }
}
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_get_matrix_dimensions() {
        assert_eq!(Matrix::<MPInteger>::get_matrix_dimensions(12), (3, 4));
        assert_eq!(Matrix::<MPInteger>::get_matrix_dimensions(18), (3, 6));
        assert_eq!(Matrix::<MPInteger>::get_matrix_dimensions(23), (1, 23));
    }

    #[test]
    fn test_from_rows() {
        let rows = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let m_r = Matrix::from_rows(&rows);
        assert!(m_r.is_ok());
        let m = m_r.unwrap();
        assert_eq!(m.nb_rows(), 2);
        assert_eq!(m.nb_columns(), 3);
        let mut l_iter = m.rows_iter();
        assert_eq!(l_iter.next(), Some(&vec![1, 2, 3]));
        assert_eq!(l_iter.next(), Some(&vec![4, 5, 6]));
        assert!(l_iter.next().is_none())
    }

    #[test]
    fn test_matrix() {
        let matrix = Matrix::to_matrix(&[1, 2, 3, 4, 5, 6], (2, 3)).unwrap();
        assert!(!matrix.is_malformed());
        assert_eq!(matrix.nb_rows(), 2);
        assert_eq!(matrix.nb_columns(), 3);
        assert_eq!(matrix.column(0), vec![&1, &4]);
        assert_eq!(matrix.column(1), vec![&2, &5]);
        assert_eq!(matrix.column(2), vec![&3, &6]);
        assert_eq!(matrix.row(0), vec![&1, &2, &3]);
        assert_eq!(matrix.row(1), vec![&4, &5, &6]);
        let m2 = matrix.transpose().unwrap();
        assert_eq!(m2.nb_rows(), 3);
        assert_eq!(m2.nb_columns(), 2);
        assert_eq!(m2.row(0), vec![&1, &4]);
        assert_eq!(m2.row(1), vec![&2, &5]);
        assert_eq!(m2.row(2), vec![&3, &6]);
        assert_eq!(m2.column(0), vec![&1, &2, &3]);
        assert_eq!(m2.column(1), vec![&4, &5, &6]);
    }

    #[test]
    fn test_matrix_iter() {
        let matrix = Matrix::to_matrix(&[1, 2, 3, 4, 5, 6], (2, 3)).unwrap();
        let mut c_iter = matrix.columns_iter();
        assert_eq!(c_iter.next(), Some(vec![&1, &4]));
        assert_eq!(c_iter.next(), Some(vec![&2, &5]));
        assert_eq!(c_iter.next(), Some(vec![&3, &6]));
        assert!(c_iter.next().is_none());
        let mut l_iter = matrix.rows_iter();
        assert_eq!(l_iter.next(), Some(&vec![1, 2, 3]));
        assert_eq!(l_iter.next(), Some(&vec![4, 5, 6]));
        assert!(l_iter.next().is_none())
    }
}
