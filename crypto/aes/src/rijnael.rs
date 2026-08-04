use core::ops::{Index, IndexMut};

use crate::state::{
    AES_BLOCK_LEN, NB, inv_mix_columns, inv_shift_rows, inv_sub_bytes, mix_columns, shift_rows,
    sub_bytes,
};
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{Algorithm, SecurityStrength};
use bouncycastle_utils::secret::Secret;
use core::fmt;

// TODO -- Added constants for specific runds
/* *** Algorithm names *** */

/// The library-wide name for AES with a 128-bit key.
pub const AES_128_NAME: &str = "AES-128";
/// The library-wide name for AES with a 192-bit key.
pub const AES_192_NAME: &str = "AES-192";
/// The library-wide name for AES with a 256-bit key.
pub const AES_256_NAME: &str = "AES-256";

/* *** Parameters from FIPS 197 Table 3 (Key-Block-Round Combinations) *** */

/// The AES-128 key length in bytes; `Nk = 4` words.
pub const AES128_KEY_LEN: usize = 16;
/// The AES-192 key length in bytes; `Nk = 6` words.
pub const AES192_KEY_LEN: usize = 24;
/// The AES-256 key length in bytes; `Nk = 8` words.
pub const AES256_KEY_LEN: usize = 32;

/// The number of rounds `Nr` for AES-128.
pub const AES128_NUM_ROUNDS: usize = 10;
/// The number of rounds `Nr` for AES-192.
pub const AES192_NUM_ROUNDS: usize = 12;
/// The number of rounds `Nr` for AES-256.
pub const AES256_NUM_ROUNDS: usize = 14;

/// The length of the AES-128 key schedule, in 32-bit words: `4 * (Nr + 1)` (FIPS 197 Section 5.2).
///
/// Counted in words rather than bytes, hence `WORDS` and not the library's usual `LEN` suffix.
pub const AES128_KEY_SCHEDULE_WORDS: usize = 4 * (AES128_NUM_ROUNDS + 1);
/// The length of the AES-192 key schedule, in 32-bit words: `4 * (Nr + 1)`.
pub const AES192_KEY_SCHEDULE_WORDS: usize = 4 * (AES192_NUM_ROUNDS + 1);
/// The length of the AES-256 key schedule, in 32-bit words: `4 * (Nr + 1)`.
pub const AES256_KEY_SCHEDULE_WORDS: usize = 4 * (AES256_NUM_ROUNDS + 1);

/* *** Key types *** */

/// The [`KeyMaterial`] type that [`AES128::new`] takes: a 128-bit AES key.
///
/// Using a fixed-capacity key type means a key of the wrong size for the variant is a compile
/// error rather than a runtime one.
pub type AES128Key = KeyMaterial<AES128_KEY_LEN>;
/// The [`KeyMaterial`] type that [`AES192::new`] takes: a 192-bit AES key.
pub type AES192Key = KeyMaterial<AES192_KEY_LEN>;
/// The [`KeyMaterial`] type that [`AES256::new`] takes: a 256-bit AES key.
pub type AES256Key = KeyMaterial<AES256_KEY_LEN>;

/* *** The three variants specified by FIPS 197 *** */

/// AES with a 128-bit key: 10 rounds (FIPS 197 Table 3).
pub type AES128 = AES<AES128_KEY_LEN, AES128_NUM_ROUNDS, AES128_KEY_SCHEDULE_WORDS>;
/// AES with a 192-bit key: 12 rounds (FIPS 197 Table 3).
pub type AES192 = AES<AES192_KEY_LEN, AES192_NUM_ROUNDS, AES192_KEY_SCHEDULE_WORDS>;
/// AES with a 256-bit key: 14 rounds (FIPS 197 Table 3).
pub type AES256 = AES<AES256_KEY_LEN, AES256_NUM_ROUNDS, AES256_KEY_SCHEDULE_WORDS>;

impl Algorithm for AES128 {
    const ALG_NAME: &'static str = AES_128_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl Algorithm for AES192 {
    const ALG_NAME: &'static str = AES_192_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
}

impl Algorithm for AES256 {
    const ALG_NAME: &'static str = AES_256_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}

/// Algorithm 1 CIPHER(in, Nr, w) -> state
fn Cipher<const Nr: usize>(input: State) -> State {
    // 2: state ← in  ▷ See Sec. 3.4
    // TODO -- is this clone necessary? Can we take `input: &mut State` and then act directly on it?
    //         Equivalently phrased, is there any point in AES where you still need to have the original
    //         input state, or are we free to act in-place?
    //         That said, even if we can work in-place, it's only 16 bytes and rust may actually
    //         perform faster working on a copy, so do some benching here.
    let mut state = input.clone();

    // 3: state ← AddRoundKey(state, w[0..3])  ▷ See Sec. 5.1.4

    // 4: for round from 1 to Nr − 1 do
    // 5:   state ← SubBytes(state)  ▷ See Sec. 5.1.1
    // 6:   state ← ShiftRows(state)  ▷ See Sec. 5.1.2
    // 7:   state ← MixColumns(state)  ▷ See Sec. 5.1.3
    // 8:   state ← AddRoundKey(state, w[4 ∗ round .. 4 ∗ round + 3])
    // 9: end for

    // 10: state ← SubBytes(state)
    // 11: state ← ShiftRows(state)
    // 12: state ← AddRoundKey(state, w[4 ∗ Nr .. 4 ∗ Nr + 3])

    // 13: return state  ▷ See Sec. 3.4
    state
}

/// Eqn (5.10): RotWord(\[a0, a1, a2, a3]) = \[a1, a2, a3, a0]
pub(crate) fn RotWord(word: u32) -> u32 {
    let [a0, a1, a2, a3] = word.to_le_bytes();
    u32::from_le_bytes([a1, a2, a3, a0])
}

/// Eqn (5.11): SubWord(\[a0, . . . , a3]) = \[SBOX(a0), SBOX(a1), SBOX(a2), SBOX(a3)].
pub(crate) fn SubWord(word: u32) -> u32 {
    let [mut a0, mut a1, mut a2, mut a3] = word.to_le_bytes();

    u32::from_le_bytes([a1, a2, a3, a0])
}

/// Eqn (5.9): AddRoundKey. [s'_(0,c), s'_(1,c), s'_(2,c), s'_(3,c)],s1,c,s2,c,s3,c]) = [s0,c,s1,c,s2,c,s3,c]⊕[w(4∗round+c)] for 0 ≤ c < 4
pub(crate) fn AddRoundKey(state: &mut [u8; AES_BLOCK_LEN], w: &[u32; W_WORDS], round: usize) {
    for c in 0..NB {
        let round_key_word = w[4 * round + c].to_be_bytes();
        state[4 * c] ^= round_key_word[0];
        state[4 * c + 1] ^= round_key_word[1];
        state[4 * c + 2] ^= round_key_word[2];
        state[4 * c + 3] ^= round_key_word[3];
    }
}