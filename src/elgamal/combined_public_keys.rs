use super::ElgamalError;
use crate::{ConstantsTrait, Integer, OperationsTrait};

/// Algorithm 8.13
pub fn combine_public_keys(
    p: &Integer,
    pks: &[Vec<Integer>],
) -> Result<Vec<Integer>, ElgamalError> {
    let s = pks.len();
    let upper_n = pks[0].len();
    if s == 0 {
        return Err(ElgamalError::CombinedPublicKeysInput(
            "s must not be null".to_string(),
        ));
    }
    if upper_n == 0 {
        return Err(ElgamalError::CombinedPublicKeysInput(
            "N must not be null".to_string(),
        ));
    }
    for (j, pks_j) in pks.iter().enumerate() {
        if pks_j.len() != upper_n {
            return Err(ElgamalError::CombinedPublicKeysInput(format!(
                "Size of ph_{} is {}, but must be N={}",
                j,
                pks_j.len(),
                upper_n
            )));
        }
    }

    let mut res = vec![Integer::one().clone(); upper_n];
    pks.iter().for_each(|pks_j| {
        res = pks_j
            .iter()
            .zip(res.iter())
            .map(|(pks_j_i, res_i)| res_i.mod_multiply(pks_j_i, p))
            .collect::<Vec<_>>()
    });

    if res.len() != upper_n {
        return Err(ElgamalError::CombinedPublicKeysInput(format!(
            "Size of combined keys is {}, but must be N={}",
            res.len(),
            upper_n
        )));
    }
    Ok(res)
}
