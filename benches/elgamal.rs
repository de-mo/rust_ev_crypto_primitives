use criterion::{criterion_group, criterion_main, Criterion};
use rug::Integer;
use rust_ev_crypto_primitives::{elgamal::{combine_public_keys, EncryptionParameters}, DecodeTrait};

static P_BASE64: &str = "jA4DatkpgfS1r6X1Q5iYA0sS2KakO3pabCF5uww/NyUxmZLOWP1E70Wq1jYs7FMgqAXPvfWn2cCdVGrU5ZcoHWim7FjtyhZPFw15XXewjoOsBUDoqf1Pg5mNakQpQAVEhqMRQ4s5FY1nCB5FvsAUnd8gCONEyIo75r6nj0BmZSoKYCGICT0nBnD0tpW3DwLInQZc5L+x1j39j+CGQI9wCk4+FhAyrK4nNMSsHv3vRUuxdsJber7KZ8d0eqRcyuRZdTbbBDmwz0GlxEmSrP4KRt6gohGN25y7myXQkza1alJpsNOGmBR7GSipM6/gagxRroVzAHBCVNp20g9d7UUZ32DA11pbBrjvEIWMNtZBKGr5Px4d+BJPljxBsbANBqu3d4gfrc5j0Me03yRbPwWq39r5sNFFrIMURmqaOa9l6kVkBBvgDiBt1ult+X787mO6orBoyLXMMCU8qy3zIdzCi5Kfq4Wn8i1C5af7SowhOfV33XNoRnMfPp3CSZaWi1wv";
static Q_BASE64: &str =  "RgcBtWyUwPpa19L6ocxMAaWJbFNSHb0tNhC83YYfm5KYzMlnLH6id6LVaxsWdimQVALn3vrT7OBOqjVqcsuUDrRTdix25Qsni4a8rrvYR0HWAqB0VP6nwczGtSIUoAKiQ1GIocWcisazhA8i32AKTu+QBHGiZEUd819Tx6AzMpUFMBDEBJ6Tgzh6W0rbh4FkToMucl/Y6x7+x/BDIEe4BScfCwgZVlcTmmJWD373oqXYu2EtvV9lM+O6PVIuZXIsupttghzYZ6DS4iTJVn8FI29QUQjG7c5dzZLoSZtatSk02GnDTAo9jJRUmdfwNQYo10K5gDghKm07aQeu9qKM77Bga60tg1x3iELGG2sglDV8n48O/Aknyx4g2NgGg1Xbu8QP1ucx6GPab5Itn4LVb+182Gii1kGKIzVNHNey9SKyAg3wBxA263S2/L9+dzHdUVg0ZFrmGBKeVZb5kO5hRclP1cLT+RahctP9pUYQnPq77rm0IzmPn07hJMtLRa4X";
static G_BASE64: &str =  "Ag==";

static PKS_BASE64: &[&[&str]] = &[    
    &[
        "F8Eagy7YS1k1Som6/zx3EUsXTt6+ucEo52Q4KQc/1XT+7id3YGPu4obdT8oDa0QDrCWaeDsn/xtzUqmQefEFrFxJi1BdYR1LkhgTPwOqdDRNnEQ9ExuM8+x35TM4YZsZXdDVYeaiDFoxYuK7BhaGhMZPCVavtVIlbdg8azRfpFpyQsGdq8w/VzQyKnZr4zEHqsGL6sbHkZL7Y6ekbyf8YJzr+AHIoIsuBAAwOd0piCxfXoKHNLE6irsC6z1OnjDzj+91IDEfoS8oPM+L5J/nDGUaD5R7ds65j1qJhKoSMMEB9/f+3/7GNXnIXCSqWIoCFoNJNI9c8kr3oRIkJ2Aaf6RCIccwD3UkG1dKvUBFZSwzfWCF/+qrSk1AM+kCSBO4AITzxW4IM4BJSbgyQ+EAknpBD073U4d4mplJA9urFLrXecJSl32VoYcFI5l1co8yp1tnmacXCmjdk4YsPlS3+pgj4Sr09uQcwlC4QQw+TYptxMc31JgvVkx9halfZWLV",
        "RsCQWJok85Ho9hMEZuxC1gx9WeWLmMrqobAutPQDwuq5VSwt4jVD5sa0xFijAzi65655xriZk/J5ySrP4UvXdWLaTgmjm5Nc4ErseJJimZamqhoFMjcRMlHpceHEmLF7LB10moJuKL5RcjVKXn5mf3lCrsoORZ609gO15C0JWfyYBldIs+f3GKT8tvMU3qLz6SoEnMiMsEFLaztD9FMdkh5uRDQ6fx3cnxeyK10n61UIIs0t+qEM4xZxeqBdjEWYMHxe/uEyH7NGU0cQJxDE9GWbEar5QuC6qGW4NQacXij/RsOk3zBE1QtCA81dYROEUwPSvfy8gTC+iuqZb9J3qmNwDvnOOhffvJZFJyCDFTVWiMIDdPwNBqm4NKZU6paQkKAZjpb/NAt9c7LJly6Q/dq/bedoAmViuJMoJJWMonM8UaGWB2inJzE9ZyegeKkRmYX7ss/G0eogqMvePhceTovLZCCMQKotPo+5MzJBXNOlNvRUu4T8IRYMvusxKn5A"
    ],
    &[
        "Lvtvk9D9BLYnWujc5I5y4JbQ38LpUnIoP50Yn54gmvZMRg9UT8rYV1pCQiistAJoSbbOtL+EjLjczMBxnWGXRFFl3sYOdwC7N+TJU+mHgBc/yGCRBK7D79ArFb8jR2UN2tEtwQriuzKrvf2q85yEZ3UkpgyMa+PDDT9LVgITBdbD9iffUb6rPM5KWBsNxbkzh4HOmuOIvRA03NG2SpImXiA6POabJQFgVUSaSeAS3O1GMgDXW0fZgYHRsmZWMeVZ52bKo/cFvLD5Dn5EdsSTZSVn5ziwnqRpu3IezIplZZnM9fZ3Lts+uW7fG3hu+l5Fqc5MIsGqZBpdrjAD3bqq78h5IqK4CNq6wRKX5G2ywAb90CePfqRkpny0wjNZLVzDSX334O1xUh/C1nyUy3+P0m+bMH5pA+OR+jtIx/0QUuCAD5jeHGEiCmRy2ZsdkVWbmgEfZ1+aNgHcCoQDLeb0JqXvryUXzMlMUyeHyJRBScur4vV/6vkTowMcjG2WcW0Q",
        "eZq/TxREo9YZMwCl1gBENHoBOgpV0Olh651b2CqSUaQo48mk+5wV1AtAswq7MjDgoWpYNHmFOV/AHCydAJzqoPq3Xa/j7Wd5FJjIm4z2EYiFUi4AXHTIXcfBAPvv0bxOXEeOmbWjBt5x8Wsk23zQGMdx6Q9088mflwfZglfdgFcdXW7OzeCql7zHEldiAsi/2kfAgEO23aiX8kOrQ+v+KtMMTksFBbsjcsLurWbhDOwIhoPO3x3nihHOKIQBULZAQMDyHpJGqVwCYsMXM3i66pTnRsUOArbEGSR7Qwf0wS22da7R74po9Z7W7cvT6Zl13VMnmeGVGyqTaLa6R6uU687cRkNE0npdQ9Wfi+hq2Ot1TxbWrTkns/F5B5LO827z/Y/v6O87PJrnQxBjh9K52FeBc8XNIusw+/YB5fNx/vf51QVhclYGxGq6/4HPVS5IB2S33Lh+uXVpUF9eD3fVVUdIHP2zFbYxeFzbQjfUIoNYnM/Z8lVz6+rnHMPpqUOu"
    ],
    &[
        "JjNxnVhCIjOaemJfHTSaSMWFOSav7RNIVXeyt5I0+L/Fpee/scxJ9MMqZAbZPEDcLBNCt5ag4DIn9nyy/7FJunh1NU1OnAJVA0MiCg6161jOeuTCWfso35rB1zoLP7JjMf3lKZuQwJPMAaHBz+qe8inJq5Hd34xohiMBIA+YfZi/tqIqKpcBuvI6YnL6Agy4SQi5evrPfiONf5/XEWPTFGEIUnfofcNVTEiNwqzKr5LvQEvm1or/wA0CEConZ7XOySZsE+fq7RsGwscF67zt7DBbJLczAdGqXAVpq1wi/JZZlFNDoxesHypdJTktScZpjzkQxf2LTEP42JMTQhU5mIPCGYINQGvnkLbxOsmH3+B3vM444IdOkUQz8hsDuXBUdxYDaZtalcfJi37++xsoPozUHha4DPUoTcKjtVq2YjvVjcNX3jOAUe/BibFy0n0ujcpXp1FlCRJu3NOcEY0CCqxrhzKEcPiY7joeqH4T9TaHWCXJD0GGNUCtwijRsvsc",
        "M1rqEuIbQRMFidlsjuOEMxafUY7Kd7W/NMn1GBf6l7b7KqtbL78FqUoQ/naYztcbljjDGDMTiudr4hWm/nmtjCDfmq3JmNHN6swtpHBxZCLeBvGPC/khimveHzlbIHquFtm1n0MEEF7Gm6MqZIxQ4YX1PaI5srW19rQpovzUPEhnOlPdiS9qTG1tJ59bcxQHJtgWqM5VSulbjNQDA/B9wCAXXMpshTKFt2G1IktTipfPE1saY5zADHmwBk1Gn5F7VsttUoYPE18PL5oe5bryIlzVhK/dMIMJVR2r9Xf4olsNy4Tm2mPAPmnHgNaXCFUrF3caAdDkpLqjU/dMsfyzpPfNTuHEkazLIEN3Lz2MwVcoW/kpb3fuiwZLuZa2TxuLTHNzuz8dTjFe+jj2vMshm25HgqUaOAzUGULc9nMKhEE9zT02F1/37Y2iWxWd6wHCAkXBPiASLAaX5yoR0ThEjae0g2t5RHBf/n8XVN5R9M6/XjA0LhYg/fY8RcYcWIkp"
    ],
    &[
        "dbFW94MeMPEjEss9CHw3oxf9s1AlSdRgYTXqpVYTQyc56yBth9SDvQ39AFeszxmIO5zFtdrGbnDpKALXtEXNYyA5uxchpPI4XrkBtCuUIEhih1u+CByCvf7nURbzEflENtxp7U9b1hDid+3Ia0s4alKBxIvIOT0s0aj9H44b4zVZKJAPRFnUuUL0IBOMB6J1jmMwoF2x0YUkfUO/BBfulf05o+aCY2mIY2cg5gOu7ZfBuJQdxHG8dendQAvOGest/ucmVe0TWgpCjsaBfiGlz99MJqAfZwNxsn4qIgCvIBVv24g3GB+FJJeXMezXQUxWulD4CUfEUh5sV2hyAyn6fhfK0x6Xn52xLXPXtK/ZzXflk8Z/ND4kFBJb6woMFes42fBmpsEpzlnxjtZ46ZENUZ14pt2B3OeT7iLwBtKSVwA05EPjVtGn1Y5A0wxMPNxWWAjEeegmrFdOIobSs2Qi4kTx0OETtlkZL91kH2TqwFKrfhz1wZY3+3Ot4ma1mDi0",
        "Y/cjexCdHgpBz3ncW0WYVJMJabmJZZ3ocbJK4z18h7JzhkMIjS8kTX96e59IK6Mt5qu1Xy2UK7CN6zEubautS2F3Nk350i0ghUWQpYBm8AUJ4EdfoqdlzYP5flGcqMAk9m1lpkrx8/P5vZv99TGpw6dfOaTZEGBbhNcZpiWeiv1SCs7mpmJSujZkIzb2pQE3sSCC54TEdcacPRJnoKfvDXo+rFJd7PGjts++diwGQEh9j6Eufyzt31rWUn3rQMZTlC10JWelplWunRe+EpfUjm76vLVkWga7DJ+k9vOLEeSDDZLkgPCQ2PQUOjzJIhZ+jSt6Z815rxo+wnb5ySTfNQfxWMWShgGA31c8g1/SN9CsprYAIdK9kTTXTFfzBYJxib6/D20XTJMV7Wp+jWNoLawaV4dzcELycksISzv97h30xLOIfpUkJoAA5lhh22VXltcvp59IM7S0gGjqxEBG8bSMtIzQCgzdelhU7eGFWnQBAYxkmNUp8qSWvE5JuniA"
    ],
    &[
        "XGpoh7KyNxoYpAKpCVhHWnD1aIgeJcdH/ZI7+uSHFv6mCDEGFDT5qZLNiG7a/mMqwkxhvxOWHQxXmwVdrHtqGuxZDpRAXuTLGweuLHnh5MOvEVR5PyZdm7fAnMX2Tq1P1zQD8g/nNxnD+iq+xNgZT3totcKnaGBSvjnWVdg2JxthN/c7Pc0/zbYydNGn+pSW8ywi5IVJWeo4FpfhuAidUL1a5TMTnSV7zA/KuQlcWOeiKWloLuvlxnlsSMtfyuHfw4rqNgkJAq9RpQm0c0Pe6c4Uxf7rAgjt1K4Lfk5d2hOj58oiiIUtOj79c7IcJjJFsMImqoylsC7y4bApuvBgstBf3DtvURrWIRem8cXdytSbEA2+R6FnQwaVcCErLSEMswuJojxHsrgwMKMJDcIOxVvVNQYxEXj9+Rxh8vH3Hx+IOjzIPnRqFsJhasEgIQ3PGWPEUeDza8n+KfxOiHnzV7kjFp8rdKUIZxGOIOtGhLJfwVByic0P9xkXZRxbsK5O",
        "eUvEHzUoJIzJVlyVXgaM6Cizml4j9pR2TcqwS5vONE3zdOMibKlZ2UnpV8/G3owuLTzpjrEavpm1P6yi3KZqkC2Wd+EjWs6Tzl/IZXtM9I4FC4hJNUwlTyRNk7RFjZrzq0R3LmwYbAOy01MnpnhbA1/16FjMuBUjVcwYlZwPVN2zKsNvWIIk4pt1fJhiXnhi7hfwVLdnj8RHMp7YGLGtgaUT4dDU+s7aMrpCDkZbQ28uJp1KeFyayc8jYZXhONur1dHcPnFypUud7w29BnLpSp2cXd7jk98GfZq5gd2w88jH6AkoYWEdpZHj4nNmyV7fJcNAsl1Hm7o4FqXDjNPJN3oNoihiwaa6hjTRl4koXaJdxqhoQIDI34o9iK0uZlna9afvxcXgkohu7VchuBk/zKJo8wfSD8bq2GDMq95FvYfryVzWPfpR/QBZl4rhXh4ut3P4od/ii/LaVXubJA95kcLYrJR0cVW3fpMDS9NXVslv4mb5I14u892BlfNb/cRG"
    ]
];

fn encryption_parameters() -> EncryptionParameters {
    let p = Integer::base64_decode(P_BASE64).unwrap();
    let q = Integer::base64_decode(Q_BASE64).unwrap();
    let g = Integer::base64_decode(G_BASE64).unwrap();
    EncryptionParameters::from((&p,&q,&g))
}

pub fn combine_public_keys_bench(c: &mut Criterion) {
    let p = encryption_parameters().p().clone();
    let pks = PKS_BASE64
        .iter()
        .map(|&s_slice| 
            Integer::base_64_decode_vector(s_slice
                .iter()
                .map(|&s| s.to_string()).collect::<Vec<_>>().as_slice()).unwrap())
        .collect::<Vec<_>>();
    c.bench_function("combine_public_keys", |b| b.iter(|| combine_public_keys(&p, pks.as_slice()).unwrap()));
}

pub fn get_small_prime_group_members_bench(c: &mut Criterion) {
    let ep = encryption_parameters();
    c.bench_function("get_small_prime_group_members_bench", |b| b.iter(|| ep.get_small_prime_group_members(5000)));
}

criterion_group!(benches, combine_public_keys_bench, get_small_prime_group_members_bench);
criterion_main!(benches);
