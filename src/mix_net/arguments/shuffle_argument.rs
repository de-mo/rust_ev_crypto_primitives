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

use crate::{
    integer::MPInteger,
    mix_net::{
        commitments::get_commitment_matrix,
        matrix::{Matrix, MatrixError},
    },
    zero_knowledge_proofs::Cyphertext,
    Constants, EncryptionParameters, HashError, HashableMessage, Operations, RecursiveHashTrait,
};

use super::{
    super::commitments::CommitmentKey, multi_exponentiation_argument::MultiExponentiationArgument,
    product_argument::ProductArgument,
};

/// Shuffle argument according to the speicifcation of Swiss Post
pub struct ShuffleArgument {
    pub c_upper_a: Vec<MPInteger>,
    pub c_upper_b: Vec<MPInteger>,
    pub product_argument: ProductArgument,
    pub multi_exponentiation_argument: MultiExponentiationArgument,
}

#[derive(Debug)]
pub struct VerifyShuffleArgumentResult {
    pub product_verif: bool,
    pub multi_verif: bool,
}

#[derive(Error, Debug)]
pub enum VerifyShuffleArgumentError {
    #[error("Wrong size {0} of cyphertexts {2}. Must be equal to N={1}")]
    LengthCypherText(usize, usize, String),
    #[error("n must be greater or equal 2 and less or equal nu={1}. It is {0}")]
    SmallNWorng(usize, usize),
    #[error("The size {0} of the commitemnt vector {2} must be equal to n={1}")]
    SizeCommitmentVectorWrong(usize, usize, String),
    #[error(transparent)]
    HashError(#[from] HashError),
    #[error(transparent)]
    MatrixError(#[from] MatrixError),
}

pub fn verify_shuffle_argument(
    ep: &EncryptionParameters,
    pks: &[MPInteger],
    ck: &CommitmentKey,
    (upper_cs, upper_c_primes): (&[Cyphertext], &[Cyphertext]),
    argument: &ShuffleArgument,
    (m, n): (usize, usize),
) -> Result<VerifyShuffleArgumentResult, VerifyShuffleArgumentError> {
    let upper_n = m * n;
    if upper_cs.len() != upper_n {
        return Err(VerifyShuffleArgumentError::LengthCypherText(
            upper_cs.len(),
            upper_n,
            "C".to_string(),
        ));
    }
    if upper_c_primes.len() != upper_n {
        return Err(VerifyShuffleArgumentError::LengthCypherText(
            upper_c_primes.len(),
            upper_n,
            "C'".to_string(),
        ));
    }
    if n < 2 || n > ck.nu() {
        return Err(VerifyShuffleArgumentError::SmallNWorng(n, ck.nu()));
    }
    if argument.c_upper_a.len() != m {
        return Err(VerifyShuffleArgumentError::SizeCommitmentVectorWrong(
            argument.c_upper_a.len(),
            m,
            "c_A".to_string(),
        ));
    }
    if argument.c_upper_b.len() != m {
        return Err(VerifyShuffleArgumentError::SizeCommitmentVectorWrong(
            argument.c_upper_b.len(),
            m,
            "c_B".to_string(),
        ));
    }
    let x = HashableMessage::from(get_hashable_vector_for_x(
        ep.p(),
        ep.q(),
        pks,
        ck,
        upper_cs,
        upper_c_primes,
        &argument.c_upper_a,
    ))
    .recursive_hash()
    .map_err(VerifyShuffleArgumentError::HashError)?
    .into_mp_integer();

    let y = HashableMessage::from(get_hashable_vector_for_y(
        ep.p(),
        ep.q(),
        pks,
        ck,
        upper_cs,
        upper_c_primes,
        &argument.c_upper_a,
        &argument.c_upper_b,
    ))
    .recursive_hash()
    .map_err(VerifyShuffleArgumentError::HashError)?
    .into_mp_integer();

    let z = HashableMessage::from(get_hashable_vector_for_z(
        ep.p(),
        ep.q(),
        pks,
        ck,
        upper_cs,
        upper_c_primes,
        &argument.c_upper_a,
        &argument.c_upper_b,
    ))
    .recursive_hash()
    .map_err(VerifyShuffleArgumentError::HashError)?
    .into_mp_integer();

    let upper_z_neg = Matrix::to_matrix(&vec![-z.clone(); upper_n], (m, n))
        .map_err(VerifyShuffleArgumentError::MatrixError)?
        .transpose()
        .map_err(VerifyShuffleArgumentError::MatrixError)?;

    let cs_minus_z =
        get_commitment_matrix(ep, &upper_z_neg, &vec![MPInteger::zero().clone(); m], ck);

    let c_upper_d: Vec<MPInteger> = argument
        .c_upper_a
        .iter()
        .zip(argument.c_upper_b.iter())
        .map(|(a, b)| a.mod_exponentiate(&y, ep.p()).mod_multiply(b, ep.p()))
        .collect();

    let b = (1..upper_n + 1)
        .map(|i| &y * i + x.mod_exponentiate(&MPInteger::from(i), ep.p()) - &z)
        .fold(MPInteger::one().clone(), |acc, v| {
            acc.mod_multiply(&v, ep.p())
        });
    todo!()
}

fn get_hashable_vector_for_x<'a>(
    p: &'a MPInteger,
    q: &'a MPInteger,
    pks: &'a [MPInteger],
    ck: &'a CommitmentKey,
    upper_cs: &'a [Cyphertext],
    upper_c_primes: &'a [Cyphertext],
    c_upper_a: &'a [MPInteger],
) -> Vec<HashableMessage<'a>> {
    vec![
        HashableMessage::from(p),
        HashableMessage::from(q),
        HashableMessage::from(pks),
        HashableMessage::from(ck),
        HashableMessage::from(
            upper_cs
                .iter()
                .map(HashableMessage::from)
                .collect::<Vec<HashableMessage>>(),
        ),
        HashableMessage::from(
            upper_c_primes
                .iter()
                .map(HashableMessage::from)
                .collect::<Vec<HashableMessage>>(),
        ),
        HashableMessage::from(
            c_upper_a
                .iter()
                .map(HashableMessage::from)
                .collect::<Vec<HashableMessage>>(),
        ),
    ]
}

#[allow(clippy::too_many_arguments)]
fn get_hashable_vector_for_y<'a>(
    p: &'a MPInteger,
    q: &'a MPInteger,
    pks: &'a [MPInteger],
    ck: &'a CommitmentKey,
    upper_cs: &'a [Cyphertext],
    upper_c_primes: &'a [Cyphertext],
    c_upper_a: &'a [MPInteger],
    c_upper_b: &'a [MPInteger],
) -> Vec<HashableMessage<'a>> {
    let mut res = get_hashable_vector_for_x(p, q, pks, ck, upper_cs, upper_c_primes, c_upper_a);
    res.insert(
        0,
        HashableMessage::from(
            c_upper_b
                .iter()
                .map(HashableMessage::from)
                .collect::<Vec<HashableMessage>>(),
        ),
    );
    res
}

#[allow(clippy::too_many_arguments)]
fn get_hashable_vector_for_z<'a>(
    p: &'a MPInteger,
    q: &'a MPInteger,
    pks: &'a [MPInteger],
    ck: &'a CommitmentKey,
    upper_cs: &'a [Cyphertext],
    upper_c_primes: &'a [Cyphertext],
    c_upper_a: &'a [MPInteger],
    c_upper_b: &'a [MPInteger],
) -> Vec<HashableMessage<'a>> {
    let mut res = get_hashable_vector_for_y(
        p,
        q,
        pks,
        ck,
        upper_cs,
        upper_c_primes,
        c_upper_a,
        c_upper_b,
    );
    res.insert(0, HashableMessage::from("1"));
    res
}
