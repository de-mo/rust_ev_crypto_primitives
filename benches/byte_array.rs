use criterion::{criterion_group, criterion_main, Criterion};
use rug::{rand::RandState, Integer};
use rust_ev_crypto_primitives::{random::random_bytes, ByteArray};

pub fn from_bytes_bench(c: &mut Criterion) {
    let bytes = random_bytes(1000).unwrap();
    let bytes_slice = bytes.to_bytes();
    c.bench_function("from_bytes", |b| {
        b.iter(|| ByteArray::from_bytes(bytes_slice))
    });
}

pub fn into_integer_bench(c: &mut Criterion) {
    let bytes = random_bytes(1000).unwrap();
    c.bench_function("into_integer", |b| b.iter(|| bytes.into_integer()));
}

pub fn cut_bit_length_bench(c: &mut Criterion) {
    let bytes = random_bytes(1000).unwrap();
    c.bench_function("cut_bit_length", |b| b.iter(|| bytes.cut_bit_length(299)));
}

pub fn from_integer_bench(c: &mut Criterion) {
    let mut rand = RandState::new();
    let n = Integer::from(Integer::random_bits(1024, &mut rand));
    c.bench_function("from_integer", |b| {
        b.iter(|| ByteArray::try_from(&n).unwrap())
    });
}

criterion_group!(
    benches,
    from_bytes_bench,
    into_integer_bench,
    cut_bit_length_bench,
    from_integer_bench
);
criterion_main!(benches);
