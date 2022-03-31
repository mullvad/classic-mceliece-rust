//! KEM API

use std::error;

use crate::controlbits::controlbitsfrompermutation;
#[cfg(any(feature = "mceliece6960119", feature = "mceliece6960119f"))]
use crate::params::{PK_NCOLS, PK_NROWS, PK_ROW_BYTES};
use crate::randombytes::RNGState;
use crate::{
    api::{CRYPTO_BYTES, CRYPTO_CIPHERTEXTBYTES, CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES},
    crypto_hash::shake256,
    decrypt::decrypt,
    encrypt::encrypt,
    macros::sub,
    params::{COND_BYTES, GFBITS, IRR_BYTES, SYND_BYTES, SYS_N, SYS_T},
    pk_gen::pk_gen,
    sk_gen::genpoly_gen,
    util::{load4, load_gf, store8, store_gf},
};

/// This function determines (in a constant-time manner) whether the padding bits of `pk` are all zero.
#[cfg(any(feature = "mceliece6960119", feature = "mceliece6960119f"))]
fn check_pk_padding(pk: &[u8; PK_NROWS * PK_ROW_BYTES]) -> u8 {
    let mut b = 0u8;
    for i in 0..PK_NROWS {
        b |= pk[i * PK_ROW_BYTES + PK_ROW_BYTES - 1];
    }

    b >>= PK_NCOLS % 8;
    b = b.wrapping_sub(1);
    b >>= 7;
    b.wrapping_sub(1)
}

/// This function determines (in a constant-time manner) whether the padding bits of `c` are all zero.
#[cfg(any(feature = "mceliece6960119", feature = "mceliece6960119f"))]
fn check_c_padding(c: &[u8; SYND_BYTES]) -> u8 {
    let mut b = c[SYND_BYTES - 1] >> (PK_NROWS % 8);
    b = b.wrapping_sub(1);
    b >>= 7;
    b.wrapping_sub(1)
}

/// KEM Encapsulation.
///
/// Given a public key `pk`, sample a shared key.
/// This shared key is returned through parameter `key` whereas
/// the ciphertext (meant to be used for decapsulation) is returned as `c`.
#[cfg(not(any(feature = "mceliece6960119", feature = "mceliece6960119f")))]
pub fn crypto_kem_enc(
    c: &mut [u8; CRYPTO_CIPHERTEXTBYTES],
    key: &mut [u8; CRYPTO_BYTES],
    pk: &[u8; CRYPTO_PUBLICKEYBYTES],
    rng: &mut impl RNGState,
) -> Result<(), Box<dyn error::Error>> {
    let mut two_e = [0u8; 1 + SYS_N / 8];
    two_e[0] = 2;

    let mut one_ec = [0u8; 1 + SYS_N / 8 + (SYND_BYTES + 32)];
    one_ec[0] = 1;

    encrypt(c, pk, sub!(mut two_e, 1, SYS_N / 8), rng)?;

    shake256(&mut c[SYND_BYTES..SYND_BYTES + 32], &two_e)?;

    one_ec[1..1 + SYS_N / 8].copy_from_slice(&two_e[1..1 + SYS_N / 8]);
    one_ec[1 + SYS_N / 8..1 + SYS_N / 8 + SYND_BYTES + 32].copy_from_slice(&c[0..SYND_BYTES + 32]);

    shake256(&mut key[0..32], &one_ec)?;

    Ok(())
}

/// KEM Encapsulation.
///
/// Given a public key `pk`, sample a shared key.
/// This shared key is returned through parameter `key` whereas
/// the ciphertext (meant to be used for decapsulation) is returned as `c`.
#[cfg(any(feature = "mceliece6960119", feature = "mceliece6960119f"))]
pub fn crypto_kem_enc(
    c: &mut [u8; CRYPTO_CIPHERTEXTBYTES],
    key: &mut [u8; CRYPTO_BYTES],
    pk: &[u8; CRYPTO_PUBLICKEYBYTES],
    rng: &mut impl RNGState,
) -> Result<u8, Box<dyn error::Error>> {
    let mut two_e = [0u8; 1 + SYS_N / 8];
    two_e[0] = 2;

    let mut one_ec = [0u8; 1 + SYS_N / 8 + (SYND_BYTES + 32)];
    one_ec[0] = 1;

    let padding_ok = check_pk_padding(pk);

    encrypt(c, pk, sub!(mut two_e, 1, SYS_N / 8), rng)?;

    shake256(&mut c[SYND_BYTES..(SYND_BYTES + 32)], &two_e)?;

    one_ec[1..1 + (SYS_N / 8)].copy_from_slice(&two_e[1..(SYS_N / 8) + 1]);
    one_ec[1 + (SYS_N / 8)..1 + (SYS_N / 8) + SYND_BYTES + 32]
        .copy_from_slice(&c[0..SYND_BYTES + 32]);

    shake256(&mut key[0..32], &one_ec)?;

    // clear outputs (set to all 0's) if padding bits are not all zero

    let mask = padding_ok ^ 0xFF;

    for i in 0..SYND_BYTES + 32 {
        c[i] &= mask;
    }

    for i in 0..32 {
        key[i] &= mask;
    }

    Ok(padding_ok)
}

/// KEM Decapsulation.
///
/// Given a secret key `sk` and a ciphertext `c`,
/// determine the shared text `key` negotiated by both parties.
#[cfg(not(any(feature = "mceliece6960119", feature = "mceliece6960119f")))]
pub fn crypto_kem_dec(
    key: &mut [u8; CRYPTO_BYTES],
    c: &[u8; CRYPTO_CIPHERTEXTBYTES],
    sk: &[u8; CRYPTO_SECRETKEYBYTES],
) -> Result<u8, Box<dyn error::Error>> {
    let mut conf = [0u8; 32];
    let mut two_e = [0u8; 1 + SYS_N / 8];
    two_e[0] = 2;

    let mut preimage = [0u8; 1 + SYS_N / 8 + (SYND_BYTES + 32)];

    let ret_decrypt: u8 = decrypt(
        sub!(mut two_e, 1, SYS_N / 8),
        sub!(sk, 40, IRR_BYTES + COND_BYTES),
        sub!(c, 0, SYND_BYTES),
    )?;

    shake256(&mut conf[0..32], &two_e)?;

    let mut ret_confirm: u8 = 0;
    for i in 0..32 {
        ret_confirm |= conf[i] ^ c[SYND_BYTES + i];
    }

    let mut m = (ret_decrypt | ret_confirm) as u16;
    m = m.wrapping_sub(1);
    m >>= 8;

    preimage[0] = (m & 1) as u8;

    let s = &sk[40 + IRR_BYTES + COND_BYTES..];

    for i in 0..SYS_N / 8 {
        preimage[1 + i] = (!m as u8 & s[i]) | (m as u8 & two_e[1 + i]);
    }

    for i in 0..SYND_BYTES + 32 {
        preimage[1 + (SYS_N / 8) + i] = c[i];
    }

    shake256(&mut key[0..32], &preimage)?;

    Ok(0)
}

/// KEM Decapsulation.
///
/// Given a secret key `sk` and a ciphertext `c`,
/// determine the shared text `key` negotiated by both parties.
#[cfg(any(feature = "mceliece6960119", feature = "mceliece6960119f"))]
pub fn crypto_kem_dec(
    key: &mut [u8; CRYPTO_BYTES],
    c: &[u8; CRYPTO_CIPHERTEXTBYTES],
    sk: &[u8; CRYPTO_SECRETKEYBYTES],
) -> Result<u8, Box<dyn error::Error>> {
    let mut conf = [0u8; 32];
    let mut two_e = [0u8; 1 + SYS_N / 8];
    two_e[0] = 2;

    let mut preimage = [0u8; 1 + SYS_N / 8 + (SYND_BYTES + 32)];

    let padding_ok = check_c_padding(sub!(c, 0, SYND_BYTES));

    let ret_decrypt: u8 = decrypt(
        sub!(mut two_e, 1, SYS_N / 8),
        sub!(sk, 40, IRR_BYTES + COND_BYTES),
        sub!(c, 0, SYND_BYTES),
    )?;

    shake256(&mut conf[0..32], &two_e)?;

    let mut ret_confirm: u8 = 0;
    for i in 0..32 {
        ret_confirm |= conf[i] ^ c[SYND_BYTES + i];
    }

    let mut m = (ret_decrypt | ret_confirm) as u16;
    m = m.wrapping_sub(1);
    m >>= 8;

    preimage[0] = (m & 1) as u8;

    let s = &sk[40 + IRR_BYTES + COND_BYTES..];

    for i in 0..SYS_N / 8 {
        preimage[1 + i] = (!m as u8 & s[i]) | (m as u8 & two_e[1 + i]);
    }

    for i in 0..SYND_BYTES + 32 {
        preimage[1 + (SYS_N / 8) + i] = c[i];
    }

    shake256(&mut key[0..32], &preimage)?;

    // clear outputs (set to all 1's) if padding bits are not all zero

    let mask = padding_ok;

    for i in 0..32 {
        key[i] |= mask;
    }

    Ok(padding_ok)
}

/// KEM Keypair generation.
///
/// Generate some public and secret key.
/// The public key is meant to be shared with any party,
/// but access to the secret key must be limited to the generating party.
///
/// The structure of the secret key is given by the following segments:
/// (32 bytes seed, 8 bytes pivots, IRR_BYTES bytes, COND_BYTES bytes, SYS_N/8 bytes).
/// The structure of the public key is simple: a matrix of PK_NROWS times PK_ROW_BYTES bytes.
pub fn crypto_kem_keypair(
    pk: &mut [u8; CRYPTO_PUBLICKEYBYTES],
    sk: &mut [u8; CRYPTO_SECRETKEYBYTES],
    rng: &mut impl RNGState,
) -> Result<(), Box<dyn error::Error>> {
    let mut seed = [0u8; 33];
    seed[0] = 64;

    const S_BASE: usize = 32 + 8 + IRR_BYTES + COND_BYTES;

    const SEED: usize = SYS_N / 8 + (1 << GFBITS) * 4 + SYS_T * 2;
    const IRR_POLYS: usize = SYS_N / 8 + (1 << GFBITS) * 4;
    const PERM: usize = SYS_N / 8;

    let mut r = [0u8; SEED + 32];

    #[cfg(any(
        feature = "mceliece348864f",
        feature = "mceliece460896f",
        feature = "mceliece6688128f",
        feature = "mceliece6960119f",
        feature = "mceliece8192128f"
    ))]
    let mut pivots = 0u64;
    #[cfg(any(
        feature = "mceliece348864",
        feature = "mceliece460896",
        feature = "mceliece6688128",
        feature = "mceliece6960119",
        feature = "mceliece8192128"
    ))]
    let pivots: u64;

    let mut f = [0u16; SYS_T];
    let mut irr = [0u16; SYS_T];

    let mut perm = [0u32; 1 << GFBITS];
    let mut pi = [0i16; 1 << GFBITS];

    rng.randombytes(&mut seed[1..])?;

    loop {
        // expanding and updating the seed
        shake256(&mut r[..], &seed[0..33])?;

        sk[..32].clone_from_slice(&seed[1..]);
        seed[1..].clone_from_slice(&r[r.len() - 32..]);

        // generating irreducible polynomial

        for (i, chunk) in r[IRR_POLYS..SEED].chunks(2).enumerate() {
            f[i] = load_gf(sub!(chunk, 0, 2));
        }

        if genpoly_gen(&mut irr, &mut f) != 0 {
            continue;
        }

        for (i, chunk) in sk[40..40 + IRR_BYTES].chunks_mut(2).enumerate() {
            store_gf(sub!(mut chunk, 0, 2), irr[i]);
        }

        // generating permutation

        for (i, chunk) in r[PERM..IRR_POLYS].chunks(4).enumerate() {
            perm[i] = load4(sub!(chunk, 0, 4));
        }

        #[cfg(any(
            feature = "mceliece348864f",
            feature = "mceliece460896f",
            feature = "mceliece6688128f",
            feature = "mceliece6960119f",
            feature = "mceliece8192128f"
        ))]
        {
            if pk_gen(
                pk,
                sub!(mut sk, 40, IRR_BYTES),
                &mut perm,
                &mut pi,
                &mut pivots,
            )? != 0
            {
                continue;
            }
        }
        #[cfg(any(
            feature = "mceliece348864",
            feature = "mceliece460896",
            feature = "mceliece6688128",
            feature = "mceliece6960119",
            feature = "mceliece8192128"
        ))]
        {
            if pk_gen(pk, sub!(mut sk, 40, IRR_BYTES), &mut perm, &mut pi)? != 0 {
                continue;
            }
        }

        controlbitsfrompermutation(
            &mut sk[(40 + IRR_BYTES)..(40 + IRR_BYTES + COND_BYTES)],
            &mut pi,
            GFBITS,
            1 << GFBITS,
        );

        // storing the random string s

        sk[S_BASE..(S_BASE + SYS_N / 8)].clone_from_slice(&r[0..SYS_N / 8]);

        // storing positions of the 32 pivots

        #[cfg(any(
            feature = "mceliece348864",
            feature = "mceliece460896",
            feature = "mceliece6688128",
            feature = "mceliece6960119",
            feature = "mceliece8192128"
        ))]
        {
            pivots = 0xFFFFFFFF;
        }

        store8(sub!(mut sk, 32, 8), pivots);

        break;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "mceliece8192128f", test))]
    use super::*;
    #[cfg(all(feature = "mceliece8192128f", test))]
    use crate::randombytes::AesState;
    #[cfg(all(feature = "mceliece8192128f", test))]
    use std::convert::TryFrom;

    #[test]
    #[cfg(feature = "mceliece8192128f")]
    fn test_crypto_kem_dec() -> Result<(), Box<dyn error::Error>> {
        use crate::api::{CRYPTO_CIPHERTEXTBYTES, CRYPTO_SECRETKEYBYTES};

        let mut sk = crate::TestData::new().u8vec("mceliece8192128f_sk1");
        let mut c = crate::TestData::new().u8vec("mceliece8192128f_ct1");
        let mut test_key = [0u8; 32];
        let compare_key = crate::TestData::new().u8vec("mceliece8192128f_operations_ss");

        crypto_kem_dec(&mut test_key, sub!(mut c, 0, CRYPTO_CIPHERTEXTBYTES), sub!(mut sk, 0, CRYPTO_SECRETKEYBYTES))?;

        assert_eq!(test_key, compare_key.as_slice());

        Ok(())
    }

    #[test]
    #[cfg(feature = "mceliece8192128f")]
    fn test_crypto_kem_enc() -> Result<(), Box<dyn error::Error>> {
        use crate::api::{CRYPTO_BYTES, CRYPTO_CIPHERTEXTBYTES, CRYPTO_PUBLICKEYBYTES};

        let mut c = [0u8; CRYPTO_CIPHERTEXTBYTES];
        let mut ss = [0u8; CRYPTO_BYTES];
        let mut pk = crate::TestData::new().u8vec("mceliece8192128f_pk1");
        assert_eq!(pk.len(), CRYPTO_PUBLICKEYBYTES);

        let compare_ss = crate::TestData::new().u8vec("mceliece8192128f_operations_ss");
        let compare_ct = crate::TestData::new().u8vec("mceliece8192128f_operations_enc1_ct");

        // set the same seed as in C implementation
        let entropy_input = <[u8; 48]>::try_from(
            crate::TestData::new()
                .u8vec("mceliece8192128f_operations_entropy_input")
                .as_slice(),
        )
        .unwrap();

        let mut rng_state = AesState::new();
        rng_state.randombytes_init(entropy_input);

        let mut second_seed = [0u8; 33];
        second_seed[0] = 64;

        rng_state.randombytes(&mut second_seed[1..])?;

        crypto_kem_enc(&mut c, &mut ss, sub!(mut pk, 0, CRYPTO_PUBLICKEYBYTES), &mut rng_state)?;

        assert_eq!(ss, compare_ss.as_slice());

        assert_eq!(c, compare_ct.as_slice());

        Ok(())
    }

    #[test]
    #[cfg(feature = "mceliece8192128f")]
    fn test_crypto_kem_keypair() -> Result<(), Box<dyn error::Error>> {
        use crate::api::{CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES};

        let mut pk_input = [0; CRYPTO_PUBLICKEYBYTES].to_vec();
        let mut sk_input = [0; CRYPTO_SECRETKEYBYTES].to_vec();

        let entropy_input = <[u8; 48]>::try_from(
            crate::TestData::new()
                .u8vec("mceliece8192128f_operations_entropy_input")
                .as_slice(),
        )
        .unwrap();

        let compare_sk = crate::TestData::new().u8vec("mceliece8192128f_operations_sk_expected");
        assert_eq!(compare_sk.len(), CRYPTO_SECRETKEYBYTES);

        let compare_pk = crate::TestData::new().u8vec("mceliece8192128f_operations_pk_expected");
        assert_eq!(compare_pk.len(), CRYPTO_PUBLICKEYBYTES);

        let mut rng_state = AesState::new();
        rng_state.randombytes_init(entropy_input);

        crypto_kem_keypair(sub!(mut pk_input, 0, CRYPTO_PUBLICKEYBYTES), sub!(mut sk_input, 0, CRYPTO_SECRETKEYBYTES), &mut rng_state)?;

        assert_eq!(compare_sk, sk_input);
        assert_eq!(compare_pk, pk_input);

        Ok(())
    }
}
