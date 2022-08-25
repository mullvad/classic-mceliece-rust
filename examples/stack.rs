//! Simple example illustrating shared key negotiation.

#![no_std]

use classic_mceliece_rust::{decapsulate, encapsulate, keypair};
use classic_mceliece_rust::{CRYPTO_BYTES, CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES};

use rand::thread_rng;

fn main() {
    let mut rng = thread_rng();

    // key generation
    let mut pubkey_buf = [0u8; CRYPTO_PUBLICKEYBYTES];
    let mut secret_buf = [0u8; CRYPTO_SECRETKEYBYTES];
    let (public_key, secret_key) = keypair(&mut pubkey_buf, &mut secret_buf, &mut rng);

    // encapsulation
    let mut shared_secret_bob_buf = [0u8; CRYPTO_BYTES];
    let (ciphertext, shared_secret_bob) =
        encapsulate(&public_key, &mut shared_secret_bob_buf, &mut rng);

    // decapsulation
    let mut shared_secret_alice_buf = [0u8; CRYPTO_BYTES];
    let shared_secret_alice = decapsulate(&ciphertext, &secret_key, &mut shared_secret_alice_buf);

    assert_eq!(shared_secret_bob.as_array(), shared_secret_alice.as_array())
}
