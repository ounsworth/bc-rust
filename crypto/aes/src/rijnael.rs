use core::ops::{Index, IndexMut};

use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{Algorithm, SecurityStrength};
use bouncycastle_utils::secret::Secret;

use crate::aes::{BLOCK_LEN, Nb};
use crate::key_schedule::{KeySchedule, RoundKey};
use crate::sbox::{inv_sub_bytes, sub_bytes};
use crate::state::{inv_mix_columns, inv_shift_rows, mix_columns, shift_rows};

/// Algorithm 1 Cipher(in, Nr, w) -> state
///
/// Deviations from the FIPS:
/// 1.  Effort has been made to make the function signatures match exactly with those in FIPS 197.
///     The one notable exception: all functions that act on a block or state modify it in-place instead
///     of returning a new object as the FIPS function signatures would imply.
///
/// 2.  FIPS 197 indexes the round keys by byte, so that `w[0..3]` is the first round key.
///     Here, they are indexed by word so that `w[0]` is the first round key, `w[1]` the second, etc.
fn cipher<const Nr: usize>(block: &mut [u8; BLOCK_LEN], w: &KeySchedule<Nr>) {
    // 2: state ← in  ▷ See Sec. 3.4
    let mut state = Secret::<[u8; BLOCK_LEN]>::new();
    *state = *block; // hard-copy the input data
    // todo --  Once we get this working with unit tests and benches,
    //          we should try acting directly on the block instead of making a hard-copy
    //          since that would save 16 bytes of memory. It might have a perf impact though,
    //          so we should do that change carefully with a before-and-after benchmark.

    // 3: state ← AddRoundKey(state, w[0..3])  ▷ See Sec. 5.1.4
    add_round_key(&mut state, &w[0]);

    // 4: for round from 1 to Nr − 1 do
    for round in 1..Nr {
        // 5:   state ← SubBytes(state)  ▷ See Sec. 5.1.1
        sub_bytes(&mut state);
        // 6:   state ← ShiftRows(state)  ▷ See Sec. 5.1.2
        shift_rows(&mut state);
        // 7:   state ← MixColumns(state)  ▷ See Sec. 5.1.3
        mix_columns(&mut state);
        // 8:   state ← AddRoundKey(state, w[4 ∗ round .. 4 ∗ round + 3])
        add_round_key(&mut state, &w[round]);
    } // 9: end for

    // 10-12: the final iteration, which omits InvMixColumns().
    // 10: state ← SubBytes(state)
    sub_bytes(&mut state);
    // 11: state ← ShiftRows(state)
    shift_rows(&mut state);
    // 12: state ← AddRoundKey(state, w[4 ∗ Nr .. 4 ∗ Nr + 3])
    add_round_key(&mut state, &w[Nr]);

    // 13: return state  ▷ See Sec. 3.4
    *block = *state;
}

/// Algorithm 3 InvCipher(in, Nr, w) -> state
fn inv_cipher<const Nr: usize>(block: &mut [u8; BLOCK_LEN], w: &KeySchedule<Nr>) {
    // 2: state <- in
    let mut state = Secret::<[u8; BLOCK_LEN]>::new();
    *state = *block; // hard-copy the input data

    // 3: state <- AddRoundKey(state, w[4*Nr .. 4*Nr+3])
    add_round_key(&mut state, &w[Nr]);

    // 4: for round from `Nr - 1` down to 1
    for round in (1..Nr).rev() {
        // 5: state ← InvShiftRows(state)  ▷ See Sec. 5.3.1
        inv_shift_rows(&mut state);
        // 6: state ← InvSubBytes(state)  ▷ See Sec. 5.3.2
        inv_sub_bytes(&mut state);
        // 7: state ← AddRoundKey(state, w[4 ∗ round..4 ∗ round + 3])
        add_round_key(&mut state, &w[round]);
        // 8: state ← InvMixColumns(state)  ▷ See Sec. 5.3.3
        inv_mix_columns(&mut state);
    } // 9: end for

    // 10-12: the final iteration, which omits InvMixColumns().
    // 10: state ← InvShiftRows(state)
    inv_shift_rows(&mut state);
    // 11: state ← InvSubBytes(state)
    inv_sub_bytes(&mut state);
    // 12: state ← AddRoundKey(state, w[0..3])
    add_round_key(&mut state, &w[0]);

    // 13: return state
    *block = *state;
}

/// Eqn (5.9): AddRoundKey.
/// `[s'_(0,c), s'_(1,c), s'_(2,c), s'_(3,c)] = [s_(0,c),s_(1,c),s_(2,c),s_(3,c)]⊕\[w_(4∗round+c)] for 0 ≤ c < 4`
pub(crate) fn add_round_key(state: &mut [u8; BLOCK_LEN], w: &RoundKey) {
    let [w0, w1, w2, w3] = w.to_be_bytes();
    for c in 0..Nb {
        // FIPS 197 s.3.4 defines the indexing of the state as `s[r,c] = s[r + 4c]`
        state[0 + 4 * c] ^= w0;
        state[1 + 4 * c] ^= w1;
        state[2 + 4 * c] ^= w2;
        state[3 + 4 * c] ^= w3;
    }
}

/// Eqn (5.10): `RotWord([a0, a1, a2, a3]) = [a1, a2, a3, a0]`
pub(crate) fn rot_word(word: u32) -> u32 {
    let [a0, a1, a2, a3] = word.to_be_bytes();
    u32::from_be_bytes([a1, a2, a3, a0])
}

/// Eqn (5.10): `RotWord([a0, a1, a2, a3]) = [a1, a2, a3, a0]`
pub(crate) fn rot_word_coreys_way(word: u32) -> u32 {
    word.rotate_left(8)
}
