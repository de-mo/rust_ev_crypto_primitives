use crate::{ConstantsTrait, Integer, OperationsTrait};

pub fn combine_public_keys(p: &Integer, pks: &[Vec<Integer>]) -> Vec<Integer> {
    pks.iter()
        .map(|pk_j| {
            pk_j.iter().fold(Integer::one().clone(), |acc, pk_j_i| {
                acc.mod_multiply(pk_j_i, p)
            })
        })
        .collect()
}
