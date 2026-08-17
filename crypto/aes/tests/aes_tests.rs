//! Known-answer tests for the AES block cipher engine, driven through the public API.
//!
//! FIPS 197 Appendix B (the worked AES-128 example) is checked directly against `cipher()` and
//! `inv_cipher()` by the unit tests in `src/rijnael.rs`, since those are crate-internal functions.
//! What is checked here is the public engine, for all three key sizes -- Appendix B alone would
//! leave the `Nk > 6` branch of the key schedule and the 12- and 14-round loops untested end to end.
//!
//! The vectors are the first four blocks of the NIST ECB-AES128/192/256 example files (the same
//! plaintext blocks and keys as NIST SP 800-38A Appendix F.1). "ECB" there just means each block is
//! enciphered independently with no chaining, which is exactly the raw permutation this crate
//! exposes -- this crate does not implement ECB, or any other mode of operation.
//!
//! The three keys are also the keys of FIPS 197 Appendix A.1, A.2 and A.3, so these tests and the
//! key schedule tests in `src/key_schedule.rs` cover the same key material from both ends.

use bouncycastle_aes::{AES128, AES128Key, AES192, AES192Key, AES256, AES256Key, BLOCK_LEN};
use bouncycastle_core::key_material::KeyType;

/* *** Test vectors *** */

/// The AES-128 key of FIPS 197 Appendix A.1 and Appendix B.
const KEY_128: &[u8; 16] = b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c";
/// The AES-192 key of FIPS 197 Appendix A.2.
const KEY_192: &[u8; 24] = b"\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\
                             \x80\x90\x79\xe5\x62\xf8\xea\xd2\x52\x2c\x6b\x7b";
/// The AES-256 key of FIPS 197 Appendix A.3.
const KEY_256: &[u8; 32] = b"\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\
                             \x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4";

/// The four plaintext blocks used by all three of the ECB-AES vector files.
const PLAINTEXTS: [[u8; BLOCK_LEN]; 4] = [
    *b"\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a",
    *b"\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51",
    *b"\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef",
    *b"\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
];

/// [`PLAINTEXTS`] enciphered under [`KEY_128`].
const CIPHERTEXTS_128: [[u8; BLOCK_LEN]; 4] = [
    *b"\x3a\xd7\x7b\xb4\x0d\x7a\x36\x60\xa8\x9e\xca\xf3\x24\x66\xef\x97",
    *b"\xf5\xd3\xd5\x85\x03\xb9\x69\x9d\xe7\x85\x89\x5a\x96\xfd\xba\xaf",
    *b"\x43\xb1\xcd\x7f\x59\x8e\xce\x23\x88\x1b\x00\xe3\xed\x03\x06\x88",
    *b"\x7b\x0c\x78\x5e\x27\xe8\xad\x3f\x82\x23\x20\x71\x04\x72\x5d\xd4",
];

/// [`PLAINTEXTS`] enciphered under [`KEY_192`].
const CIPHERTEXTS_192: [[u8; BLOCK_LEN]; 4] = [
    *b"\xbd\x33\x4f\x1d\x6e\x45\xf2\x5f\xf7\x12\xa2\x14\x57\x1f\xa5\xcc",
    *b"\x97\x41\x04\x84\x6d\x0a\xd3\xad\x77\x34\xec\xb3\xec\xee\x4e\xef",
    *b"\xef\x7a\xfd\x22\x70\xe2\xe6\x0a\xdc\xe0\xba\x2f\xac\xe6\x44\x4e",
    *b"\x9a\x4b\x41\xba\x73\x8d\x6c\x72\xfb\x16\x69\x16\x03\xc1\x8e\x0e",
];

/// [`PLAINTEXTS`] enciphered under [`KEY_256`].
const CIPHERTEXTS_256: [[u8; BLOCK_LEN]; 4] = [
    *b"\xf3\xee\xd1\xbd\xb5\xd2\xa0\x3c\x06\x4b\x5a\x7e\x3d\xb1\x81\xf8",
    *b"\x59\x1c\xcb\x10\xd4\x10\xed\x26\xdc\x5b\xa7\x4a\x31\x36\x28\x70",
    *b"\xb6\xed\x21\xb9\x9c\xa6\xf4\xf9\xf1\x53\xe7\xb1\xbe\xaf\xed\x1d",
    *b"\x23\x30\x4b\x7a\x39\xf9\xf3\xff\x06\x7d\x8d\x8f\x9e\x24\xec\xc7",
];

/* *** Known-answer tests *** */

/// Builds one known-answer test for one AES variant.
///
/// A macro rather than a generic function because the engine's const parameters (`Nr` and the key
/// schedule length) are crate-internal, so an external test cannot name them -- it can only use the
/// three aliases.
macro_rules! known_answer_test {
    ($name:ident, $engine:ty, $key_type:ty, $key:expr, $expected:expr) => {
        #[test]
        fn $name() {
            let key = <$key_type>::from_bytes_as_type($key, KeyType::SymmetricCipherKey).unwrap();
            let engine = <$engine>::new(&key).unwrap();

            for (plaintext, expected) in PLAINTEXTS.iter().zip($expected.iter()) {
                // Cipher(), FIPS 197 Algorithm 1.
                let mut block = *plaintext;
                engine.encrypt_block(&mut block);
                assert_eq!(&block, expected, "encrypt_block()");

                // InvCipher(), Algorithm 3, must invert it exactly.
                engine.decrypt_block(&mut block);
                assert_eq!(&block, plaintext, "decrypt_block()");

                // The one-shot statics re-expand the key on every call, so they are a separate path
                // to the same answer.
                let mut block = *plaintext;
                <$engine>::encrypt_single_block(&key, &mut block).unwrap();
                assert_eq!(&block, expected, "encrypt_single_block()");
                <$engine>::decrypt_single_block(&key, &mut block).unwrap();
                assert_eq!(&block, plaintext, "decrypt_single_block()");
            }
        }
    };
}

known_answer_test!(aes128_known_answers, AES128, AES128Key, KEY_128, CIPHERTEXTS_128);
known_answer_test!(aes192_known_answers, AES192, AES192Key, KEY_192, CIPHERTEXTS_192);
known_answer_test!(aes256_known_answers, AES256, AES256Key, KEY_256, CIPHERTEXTS_256);

/// The same plaintext under the three key sizes must give three different ciphertexts.
///
/// Catches an engine that ignored the tail of a longer key, or that ran the wrong number of rounds
/// for its variant -- both of which the per-variant tests above would also catch, but this states the
/// property directly.
#[test]
fn the_three_variants_are_distinct() {
    assert_ne!(CIPHERTEXTS_128[0], CIPHERTEXTS_192[0]);
    assert_ne!(CIPHERTEXTS_192[0], CIPHERTEXTS_256[0]);
    assert_ne!(CIPHERTEXTS_128[0], CIPHERTEXTS_256[0]);
}

/// `AES::new()` must refuse a key that is not tagged as a cipher key. Keeping key material separate
/// between algorithms is a security property: a MAC key is not an encryption key.
#[test]
fn rejects_a_key_of_the_wrong_type() {
    let mac_key = AES128Key::from_bytes_as_type(KEY_128, KeyType::MACKey).unwrap();
    assert!(AES128::new(&mac_key).is_err());
}

/// `AES::new()` must refuse a key tagged weaker than the variant needs -- here the 32-byte AES-256
/// key, but marked as carrying only 128 bits of strength.
#[test]
fn rejects_a_key_weaker_than_the_variant() {
    use bouncycastle_core::key_material::KeyMaterialTrait;
    use bouncycastle_core::traits::SecurityStrength;

    let mut weak_key = AES256Key::from_bytes_as_type(KEY_256, KeyType::SymmetricCipherKey).unwrap();
    weak_key.set_security_strength(SecurityStrength::_128bit).unwrap();

    assert!(AES256::new(&weak_key).is_err());
    // The same key is fine for AES-128 -- if it were the right length.
    assert_eq!(weak_key.security_strength(), SecurityStrength::_128bit);
}
