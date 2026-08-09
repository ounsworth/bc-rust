use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_core::traits::{AEADCipher, Algorithm, BlockCipher, SecurityStrength};

/* *** Parameters from FIPS 197 Table 3 (Key-Block-Round Combinations) *** */

/// The AES-128 key length in bytes; `Nk = 4` words.
pub const AES128_KEY_LEN: usize = 16;
/// The AES-192 key length in bytes; `Nk = 6` words.
pub const AES192_KEY_LEN: usize = 24;
/// The AES-256 key length in bytes; `Nk = 8` words.
pub const AES256_KEY_LEN: usize = 32;

/// The number of words in the state is denoted Nb for Rinjdael in general; in AES Nb=4.
pub(crate) const Nb: usize = 4;

/// The number of rounds `Nr` for AES-128.
pub(crate) const AES128_Nr: usize = 10;
/// The number of rounds `Nr` for AES-192.
pub(crate) const AES192_Nr: usize = 12;
/// The number of rounds `Nr` for AES-256.
pub(crate) const AES256_Nr: usize = 14;

/// The AES block length in bytes. Every AES variant has a 128-bit block (FIPS 197 Table 3).
pub(crate) const BLOCK_LEN: usize = 16;

// Dev note: once generic_const_exprs lands in rust stable, we'll be able to delete these
//           and calculate them in-place from Nr.
/// The length of, ie number of round keys in, the AES-128 key schedule, in 32-bit words: `4 * (Nr + 1) = 44` (FIPS 197 Section 5.2).
pub(crate) const AES128_Nroundkeys: usize = 4 * (AES128_Nr + 1); // 44
/// The length of, ie number of round keys in, the AES-192 key schedule, in 32-bit words: `4 * (Nr + 1) = 52` (FIPS 197 Section 5.2).
pub(crate) const AES192_Nroundkeys: usize = 4 * (AES192_Nr + 1);
/// The length of, ie number of round keys in, the AES-256 key schedule, in 32-bit words: `4 * (Nr + 1) = 60` (FIPS 197 Section 5.2).
pub(crate) const AES256_Nroundkeys: usize = 4 * (AES256_Nr + 1);

/* *** Key types *** */

/// The [`KeyMaterial`] type that [`AES128::new`] takes: a 128-bit AES key.
pub type AES128Key = KeyMaterial<AES128_KEY_LEN>;
/// The [`KeyMaterial`] type that [`AES192::new`] takes: a 192-bit AES key.
pub type AES192Key = KeyMaterial<AES192_KEY_LEN>;
/// The [`KeyMaterial`] type that [`AES256::new`] takes: a 256-bit AES key.
pub type AES256Key = KeyMaterial<AES256_KEY_LEN>;

/* *** TODO: Modes *** */

/* *** AES_CBC *** */
// Defined in SP 800-38a section 6.2
// todo -- there are other modes defined in SP 800-38a, but I don't think they ever really got used.

pub type AES128_CBC = AES_CBC<AES128_KEY_LEN, AES128_Nr>;
pub type AES192_CBC = AES_CBC<AES192_KEY_LEN, AES192_Nr>;
pub type AES256_CBC = AES_CBC<AES256_KEY_LEN, AES256_Nr>;

pub struct AES_CBC<const KEY_LEN: usize, const Nr: usize> {
    // todo
}

// impl BlockCipher<> for AES_CBC {
//     // todo
// }

/* *** AES_GCM *** */

pub type AES128_GCM = AES_GCM<AES128_KEY_LEN, AES128_Nr>;
pub type AES192_GCM = AES_GCM<AES192_KEY_LEN, AES192_Nr>;
pub type AES256_GCM = AES_GCM<AES256_KEY_LEN, AES256_Nr>;

pub struct AES_GCM<const KEY_LEN: usize, const Nr: usize> {
    // todo
}

// impl AEADCipher<> for AES_GCM {
//     // todo
// }

// todo --  Other modes we could implement:
//          * AES_CTR (SP 800-38A), it's sortof a bad stream cipher, but it's possible that it's
//            used in some protocol that could make it worthwhile to implement in bc-rust.
//          * AES_CCM (RFC4309 / NIST SP 800-38C), it's sortof an early version of what
//            we now call an AEAD and its use was largely replaced by AES_GCM once that was invented.
//            it's possible that it's used in some protocol that could make it worthwhile to implement in bc-rust.
