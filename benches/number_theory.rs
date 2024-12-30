use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rust_ev_crypto_primitives::SmallPrimeTrait;

pub fn is_small_prime_bench(c: &mut Criterion) {
    let fn_bench = |b: &mut criterion::Bencher<'_>, nb: &usize| {
        b.iter(|| nb.is_small_prime().unwrap());
    };
    c.bench_with_input(
        BenchmarkId::new("is_small_prime prime", 104730),
        &104730,
        fn_bench,
    );
    c.bench_with_input(
        BenchmarkId::new("is_small_prime not prime", 111317),
        &111317,
        fn_bench,
    );
}

criterion_group!(benches, is_small_prime_bench);
criterion_main!(benches);
