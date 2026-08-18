use bouncycastle_utils::secret::Secret;

use crate::aes::{BLOCK_LEN, Nb};
use crate::key_schedule::{KeySchedule, KeyScheduleEIC, RoundKey};
use crate::sbox::{inv_sub_bytes, sub_bytes};
use crate::state::{inv_mix_columns, inv_shift_rows, mix_columns, shift_rows};

/// Algorithm 1 Cipher(in, Nr, w) -> state
///
/// Deviations from the FIPS:
/// 1.  Effort has been made to make the function signatures match exactly with those in FIPS 197.
///     The one notable exception: all functions that act on a block or state modify it in-place instead
///     of returning a new object as the FIPS function signatures would imply.
///
/// 2.  FIPS 197 slices the key schedule at each call site, passing `w[4 ∗ round .. 4 ∗ round + 3]`
///     into AddRoundKey(). Here [`add_round_key`] takes the whole schedule plus the round number and
///     does that indexing itself, because rust cannot take a fixed-size sub-array of an array by
///     reference without copying it -- and the schedule is secret, so it should not be copied.
///
/// 3.  `Nroundkeys` (the length of the key schedule in words, `4 * (Nr + 1)`) has to be carried as a
///     second const parameter alongside `Nr`, because rust cannot yet compute one array length from
///     another const parameter. See the dev note on [`KeySchedule`]. The two must agree; the debug
///     assertion below and `AES::VALID_PARAMS` both check that they do.
pub(crate) fn cipher<const Nr: usize, const Nroundkeys: usize>(
    block: &mut [u8; BLOCK_LEN],
    w: &KeySchedule<Nroundkeys>,
) {
    // Sec 5.2: the schedule holds four words for each of the Nr + 1 AddRoundKey() calls.
    debug_assert_eq!(Nroundkeys, 4 * (Nr + 1));

    // 2: state ← in  ▷ See Sec. 3.4
    let mut state = Secret::<[u8; BLOCK_LEN]>::new();
    *state = *block; // hard-copy the input data
    // TODO --  Once we get this working with unit tests and benches,
    //          we should try acting directly on the block instead of making a hard-copy
    //          since that would save 16 bytes of memory. It might have a perf impact though,
    //          so we should do that change carefully with a before-and-after benchmark.

    // 3: state ← AddRoundKey(state, w[0..3])  ▷ See Sec. 5.1.4
    add_round_key(&mut state, w.words(), 0);

    // 4: for round from 1 to Nr − 1 do
    for round in 1..Nr {
        // 5:   state ← SubBytes(state)  ▷ See Sec. 5.1.1
        sub_bytes(&mut state);
        // 6:   state ← ShiftRows(state)  ▷ See Sec. 5.1.2
        shift_rows(&mut state);
        // 7:   state ← MixColumns(state)  ▷ See Sec. 5.1.3
        mix_columns(&mut state);
        // 8:   state ← AddRoundKey(state, w[4 ∗ round .. 4 ∗ round + 3])
        add_round_key(&mut state, w.words(), round);
    } // 9: end for

    // 10-12: the final iteration, which omits MixColumns().
    // 10: state ← SubBytes(state)
    sub_bytes(&mut state);
    // 11: state ← ShiftRows(state)
    shift_rows(&mut state);
    // 12: state ← AddRoundKey(state, w[4 ∗ Nr .. 4 ∗ Nr + 3])
    add_round_key(&mut state, w.words(), Nr);

    // 13: return state  ▷ See Sec. 3.4
    *block = *state;
}

/// Algorithm 3 InvCipher(in, Nr, w) -> state
///
/// The same deviations from the FIPS apply as for [`cipher`].
pub(crate) fn inv_cipher<const Nr: usize, const Nroundkeys: usize>(
    block: &mut [u8; BLOCK_LEN],
    w: &KeySchedule<Nroundkeys>,
) {
    debug_assert_eq!(Nroundkeys, 4 * (Nr + 1));

    // 2: state <- in
    let mut state = Secret::<[u8; BLOCK_LEN]>::new();
    *state = *block; // hard-copy the input data

    // 3: state <- AddRoundKey(state, w[4*Nr .. 4*Nr+3])
    add_round_key(&mut state, w.words(), Nr);

    // 4: for round from `Nr - 1` down to 1
    for round in (1..Nr).rev() {
        // 5: state ← InvShiftRows(state)  ▷ See Sec. 5.3.1
        inv_shift_rows(&mut state);
        // 6: state ← InvSubBytes(state)  ▷ See Sec. 5.3.2
        inv_sub_bytes(&mut state);
        // 7: state ← AddRoundKey(state, w[4 ∗ round..4 ∗ round + 3])
        add_round_key(&mut state, w.words(), round);
        // 8: state ← InvMixColumns(state)  ▷ See Sec. 5.3.3
        inv_mix_columns(&mut state);
    } // 9: end for

    // 10-12: the final iteration, which omits InvMixColumns().
    // 10: state ← InvShiftRows(state)
    inv_shift_rows(&mut state);
    // 11: state ← InvSubBytes(state)
    inv_sub_bytes(&mut state);
    // 12: state ← AddRoundKey(state, w[0..3])
    add_round_key(&mut state, w.words(), 0);

    // 13: return state
    *block = *state;
}

/// Algorithm 4 EqInvCipher(in, Nr, dw) -> state
///
/// Transformations of round function of Alg 1 Cipher are replaced by inverses
/// while also utilizing a modified key schedule: Algorithm 5, KeyExpansionEIC()
///
/// `dw` is a [`KeyScheduleEIC`], which only [`crate::key_schedule::key_expansion_eic`] can produce.
/// That is what stops the `w` from [`crate::key_schedule::key_expansion`] being passed here (or a
/// `dw` being passed to [`cipher`]): the two schedules have the same shape and would decrypt to
/// silent garbage if swapped, so they are separate types and the swap does not compile.
#[allow(dead_code)] // Not wired into the engine yet: see the EqInvCipher item in aes_dev_plan.md,
// which calls for measuring the perf/size tradeoff against inv_cipher() before deciding whether to
// keep both or only one. Exercised by the tests at the bottom of this file in the meantime.
pub(crate) fn eq_inv_cipher<const Nr: usize, const Nroundkeys: usize>(
    block: &mut [u8; BLOCK_LEN],
    dw: &KeyScheduleEIC<Nroundkeys>,
) {
    debug_assert_eq!(Nroundkeys, 4 * (Nr + 1));

    // 2: state ← in
    let mut state = Secret::<[u8; BLOCK_LEN]>::new();
    *state = *block; // hard-copy the input data

    // 3: state ← ADDROUNDKEY(state,dw[4 ∗Nr..4 ∗Nr +3])
    add_round_key(&mut state, dw.words(), Nr);

    // 4: for round from `Nr - 1` down to 1
    for round in (1..Nr).rev() {
        // 5: state ← InvSubBytes(state)  ▷ See Sec. 5.3.2
        inv_sub_bytes(&mut state);
        // 6: state ← InvShiftRows(state) ▷ See Sec. 5.3.1
        inv_shift_rows(&mut state);
        // 7: state ← InvMixColumns(state) ▷ See Sec. 5.3.3
        inv_mix_columns(&mut state);
        // 8: state ← ADDROUNDKEY(state,dw[4 ∗ round..4 ∗ round +3]) ▷ See Sec. 5.1.4
        add_round_key(&mut state, dw.words(), round);
    }

    // 10: state ← InvSubBytes(state)
    inv_sub_bytes(&mut state);
    // 11: state ← InvShiftRows(state)
    inv_shift_rows(&mut state);
    // 12: state ← ADDROUNDKEY(state,dw[0..3])
    add_round_key(&mut state, dw.words(), 0);

    *block = *state;
}

/// Eqn (5.9): AddRoundKey.
/// `[s'_(0,c), s'_(1,c), s'_(2,c), s'_(3,c)] = [s_(0,c),s_(1,c),s_(2,c),s_(3,c)]⊕\[w_(4∗round+c)] for 0 ≤ c < 4`
///
/// A round key is four words of the key schedule (Sec 5.1.4), one word per column of the state, so
/// column `c` is XORed with `w[4 * round + c]` -- a *different* word for each column.
///
/// `round` runs over `0 ..= Nr` and the schedule holds `4 * (Nr + 1)` words (Sec 5.2), so
/// `4 * round + c` is always in bounds.
///
/// Takes the schedule's words rather than a schedule, because this transformation is the one thing
/// that genuinely does not care which of the two it is given: it XORs whatever round key it is
/// handed. Keeping the [`KeySchedule`] / [`KeyScheduleEIC`] distinction at the level of the
/// algorithms that must not be confused -- [`cipher`] and [`eq_inv_cipher`] -- is what makes the
/// mismatch impossible without making this function generic over both.
pub(crate) fn add_round_key<const Nroundkeys: usize>(
    state: &mut [u8; BLOCK_LEN],
    w: &[RoundKey; Nroundkeys],
    round: usize,
) {
    for c in 0..Nb {
        // The bytes of a key schedule word are its big-endian bytes (Sec 3.5).
        let [w0, w1, w2, w3] = w[4 * round + c].to_be_bytes();

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
///
/// Equivalent to [`rot_word`] -- a word is stored big-endian, so rotating its four bytes left by one
/// position is a rotate of the whole word left by 8 bits -- and it compiles to a single instruction.
///
/// Compiled only for tests, where `rot_word_implementations_agree()` pins the equivalence, so that
/// swapping it in is a one-line change whenever the Phase 3 optimization pass gets here. Not swapped
/// in now, so that the implementation the Appendix A key schedule tests already exercise stays the
/// one in use.
#[cfg(test)]
pub(crate) fn rot_word_coreys_way(word: u32) -> u32 {
    word.rotate_left(8)
}

/// Test the constructs in this file that are crate-internal and therefore not testable from
/// the external unit tests.
#[cfg(test)]
mod rijndael_tests {
    use super::*;
    use crate::aes::{AES128_KEY_LEN, AES128_Nr, AES128_Nroundkeys};
    use crate::aes::{AES192_KEY_LEN, AES192_Nr, AES192_Nroundkeys};
    use crate::aes::{AES256_KEY_LEN, AES256_Nr, AES256_Nroundkeys};
    use crate::key_schedule::{key_expansion, key_expansion_eic};
    use bouncycastle_core::key_material::{
        KeyMaterial, KeyMaterial128, KeyMaterial192, KeyMaterial256, KeyType,
    };
    use bouncycastle_core_test_framework::DUMMY_SEED;
    // `println!` is not in scope in a no_std crate; see the `extern crate std` in lib.rs.
    use std::println;

    /* FIPS 197 Appendix B ("Cipher Example") is a worked AES-128 example:
     *
     *     Input = 32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34
     *     Key   = 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
     *
     * The key is the same one as in Appendix A.1, so the round keys consumed below are exactly the
     * values that `key_schedule::key_schedule_tests::appdx_a1` checks.
     *
     * The appendix prints each state as a 4x4 grid, which is read out into the flat byte order used
     * here column by column, per Eq (3.6) `s[r, c] = in[r + 4c]`. */

    /// Appendix B, the "input" row.
    const APPDX_B_PLAINTEXT: [u8; BLOCK_LEN] =
        *b"\x32\x43\xf6\xa8\x88\x5a\x30\x8d\x31\x31\x98\xa2\xe0\x37\x07\x34";
    /// Appendix B, the "output" row: the result of Cipher() after all 10 rounds.
    const APPDX_B_CIPHERTEXT: [u8; BLOCK_LEN] =
        *b"\x39\x25\x84\x1d\x02\xdc\x09\xfb\xdc\x11\x85\x97\x19\x6a\x0b\x32";
    /// Appendix B, round 1 "Start of Round": the state after the initial AddRoundKey() and nothing
    /// else.
    const APPDX_B_ROUND1_START: [u8; BLOCK_LEN] =
        *b"\x19\x3d\xe3\xbe\xa0\xf4\xe2\x2b\x9a\xc6\x8d\x2a\xe9\xf8\x48\x08";

    /// The Appendix A.1 / Appendix B key.
    fn appdx_b_key() -> KeyMaterial128 {
        KeyMaterial128::from_bytes_as_type(
            b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
            KeyType::SymmetricCipherKey,
        )
        .unwrap()
    }

    /* Appendix B end to end -- "this key and this plaintext give this ciphertext" -- is externally
     * observable, so it is an integration test: `appdx_b_cipher_example` in `tests/aes_tests.rs`
     * drives it through `AES128`. What is left here is the part that cannot be seen from outside the
     * crate: the individual transformations and the per-round intermediate states. */

    /// [`add_round_key`] on its own, against Appendix B's round 1 "Start of Round" state.
    ///
    /// Worth pinning separately from the end-to-end Appendix B test: this is the one transformation
    /// that has to index into the key schedule, and a version that XORed a single word into all four
    /// columns -- rather than the four distinct words `w[4 * round + c]` -- would still be its own
    /// inverse, and so would pass any test that only checks that decryption undoes encryption.
    #[test]
    fn add_round_key_matches_fips197_appdx_b() {
        let w = key_expansion::<AES128_KEY_LEN, AES128_Nroundkeys>(&appdx_b_key());

        // Round 0 is the initial AddRoundKey() of Algorithm 1 line 3, which XORs w[0..4] -- ie the
        // key itself -- into the plaintext.
        let mut state = APPDX_B_PLAINTEXT;
        add_round_key(&mut state, w.words(), 0);
        assert_eq!(state, APPDX_B_ROUND1_START);

        // AddRoundKey() is its own inverse (Sec 5.3.4).
        add_round_key(&mut state, w.words(), 0);
        assert_eq!(state, APPDX_B_PLAINTEXT);
    }

    /* *** Appendix B, the full round-by-round table *** */

    /// One row of the Appendix B table: the state at each stage of one round, plus that round's
    /// round key.
    struct AppdxBRound {
        /// The "Start of Round" column.
        start: [u8; BLOCK_LEN],
        /// The "After SubBytes" column.
        after_sub_bytes: [u8; BLOCK_LEN],
        /// The "After ShiftRows" column.
        after_shift_rows: [u8; BLOCK_LEN],
        /// The "After MixColumns" column. `None` for round Nr, which omits MixColumns() (Alg 1
        /// lines 10-12).
        after_mix_columns: Option<[u8; BLOCK_LEN]>,
        /// The "Round Key Value" column, ie `w[4 * round .. 4 * round + 4]` as bytes.
        round_key: [u8; BLOCK_LEN],
    }

    /// Every intermediate value of FIPS 197 Appendix B, rounds 1 to 10.
    ///
    /// Each 4x4 grid in the appendix is transcribed here in the flat byte order of this
    /// implementation, ie read down the columns (Eq 3.6). The "Round Key Value" entries are
    /// independently the `w[i]` values of Appendix A.1, which is a useful cross-check that this
    /// transcription is right.
    const APPDX_B_ROUNDS: [AppdxBRound; 10] = [
        // Round 1
        AppdxBRound {
            start: *b"\x19\x3d\xe3\xbe\xa0\xf4\xe2\x2b\x9a\xc6\x8d\x2a\xe9\xf8\x48\x08",
            after_sub_bytes: *b"\xd4\x27\x11\xae\xe0\xbf\x98\xf1\xb8\xb4\x5d\xe5\x1e\x41\x52\x30",
            after_shift_rows: *b"\xd4\xbf\x5d\x30\xe0\xb4\x52\xae\xb8\x41\x11\xf1\x1e\x27\x98\xe5",
            after_mix_columns: Some(
                *b"\x04\x66\x81\xe5\xe0\xcb\x19\x9a\x48\xf8\xd3\x7a\x28\x06\x26\x4c",
            ),
            round_key: *b"\xa0\xfa\xfe\x17\x88\x54\x2c\xb1\x23\xa3\x39\x39\x2a\x6c\x76\x05",
        },
        // Round 2
        AppdxBRound {
            start: *b"\xa4\x9c\x7f\xf2\x68\x9f\x35\x2b\x6b\x5b\xea\x43\x02\x6a\x50\x49",
            after_sub_bytes: *b"\x49\xde\xd2\x89\x45\xdb\x96\xf1\x7f\x39\x87\x1a\x77\x02\x53\x3b",
            after_shift_rows: *b"\x49\xdb\x87\x3b\x45\x39\x53\x89\x7f\x02\xd2\xf1\x77\xde\x96\x1a",
            after_mix_columns: Some(
                *b"\x58\x4d\xca\xf1\x1b\x4b\x5a\xac\xdb\xe7\xca\xa8\x1b\x6b\xb0\xe5",
            ),
            round_key: *b"\xf2\xc2\x95\xf2\x7a\x96\xb9\x43\x59\x35\x80\x7a\x73\x59\xf6\x7f",
        },
        // Round 3
        AppdxBRound {
            start: *b"\xaa\x8f\x5f\x03\x61\xdd\xe3\xef\x82\xd2\x4a\xd2\x68\x32\x46\x9a",
            after_sub_bytes: *b"\xac\x73\xcf\x7b\xef\xc1\x11\xdf\x13\xb5\xd6\xb5\x45\x23\x5a\xb8",
            after_shift_rows: *b"\xac\xc1\xd6\xb8\xef\xb5\x5a\x7b\x13\x23\xcf\xdf\x45\x73\x11\xb5",
            after_mix_columns: Some(
                *b"\x75\xec\x09\x93\x20\x0b\x63\x33\x53\xc0\xcf\x7c\xbb\x25\xd0\xdc",
            ),
            round_key: *b"\x3d\x80\x47\x7d\x47\x16\xfe\x3e\x1e\x23\x7e\x44\x6d\x7a\x88\x3b",
        },
        // Round 4
        AppdxBRound {
            start: *b"\x48\x6c\x4e\xee\x67\x1d\x9d\x0d\x4d\xe3\xb1\x38\xd6\x5f\x58\xe7",
            after_sub_bytes: *b"\x52\x50\x2f\x28\x85\xa4\x5e\xd7\xe3\x11\xc8\x07\xf6\xcf\x6a\x94",
            after_shift_rows: *b"\x52\xa4\xc8\x94\x85\x11\x6a\x28\xe3\xcf\x2f\xd7\xf6\x50\x5e\x07",
            after_mix_columns: Some(
                *b"\x0f\xd6\xda\xa9\x60\x31\x38\xbf\x6f\xc0\x10\x6b\x5e\xb3\x13\x01",
            ),
            round_key: *b"\xef\x44\xa5\x41\xa8\x52\x5b\x7f\xb6\x71\x25\x3b\xdb\x0b\xad\x00",
        },
        // Round 5
        AppdxBRound {
            start: *b"\xe0\x92\x7f\xe8\xc8\x63\x63\xc0\xd9\xb1\x35\x50\x85\xb8\xbe\x01",
            after_sub_bytes: *b"\xe1\x4f\xd2\x9b\xe8\xfb\xfb\xba\x35\xc8\x96\x53\x97\x6c\xae\x7c",
            after_shift_rows: *b"\xe1\xfb\x96\x7c\xe8\xc8\xae\x9b\x35\x6c\xd2\xba\x97\x4f\xfb\x53",
            after_mix_columns: Some(
                *b"\x25\xd1\xa9\xad\xbd\x11\xd1\x68\xb6\x3a\x33\x8e\x4c\x4c\xc0\xb0",
            ),
            round_key: *b"\xd4\xd1\xc6\xf8\x7c\x83\x9d\x87\xca\xf2\xb8\xbc\x11\xf9\x15\xbc",
        },
        // Round 6
        AppdxBRound {
            start: *b"\xf1\x00\x6f\x55\xc1\x92\x4c\xef\x7c\xc8\x8b\x32\x5d\xb5\xd5\x0c",
            after_sub_bytes: *b"\xa1\x63\xa8\xfc\x78\x4f\x29\xdf\x10\xe8\x3d\x23\x4c\xd5\x03\xfe",
            after_shift_rows: *b"\xa1\x4f\x3d\xfe\x78\xe8\x03\xfc\x10\xd5\xa8\xdf\x4c\x63\x29\x23",
            after_mix_columns: Some(
                *b"\x4b\x86\x8d\x6d\x2c\x4a\x89\x80\x33\x9d\xf4\xe8\x37\xd2\x18\xd8",
            ),
            round_key: *b"\x6d\x88\xa3\x7a\x11\x0b\x3e\xfd\xdb\xf9\x86\x41\xca\x00\x93\xfd",
        },
        // Round 7
        AppdxBRound {
            start: *b"\x26\x0e\x2e\x17\x3d\x41\xb7\x7d\xe8\x64\x72\xa9\xfd\xd2\x8b\x25",
            after_sub_bytes: *b"\xf7\xab\x31\xf0\x27\x83\xa9\xff\x9b\x43\x40\xd3\x54\xb5\x3d\x3f",
            after_shift_rows: *b"\xf7\x83\x40\x3f\x27\x43\x3d\xf0\x9b\xb5\x31\xff\x54\xab\xa9\xd3",
            after_mix_columns: Some(
                *b"\x14\x15\xb5\xbf\x46\x16\x15\xec\x27\x46\x56\xd7\x34\x2a\xd8\x43",
            ),
            round_key: *b"\x4e\x54\xf7\x0e\x5f\x5f\xc9\xf3\x84\xa6\x4f\xb2\x4e\xa6\xdc\x4f",
        },
        // Round 8
        AppdxBRound {
            start: *b"\x5a\x41\x42\xb1\x19\x49\xdc\x1f\xa3\xe0\x19\x65\x7a\x8c\x04\x0c",
            after_sub_bytes: *b"\xbe\x83\x2c\xc8\xd4\x3b\x86\xc0\x0a\xe1\xd4\x4d\xda\x64\xf2\xfe",
            after_shift_rows: *b"\xbe\x3b\xd4\xfe\xd4\xe1\xf2\xc8\x0a\x64\x2c\xc0\xda\x83\x86\x4d",
            after_mix_columns: Some(
                *b"\x00\x51\x2f\xd1\xb1\xc8\x89\xff\x54\x76\x6d\xcd\xfa\x1b\x99\xea",
            ),
            round_key: *b"\xea\xd2\x73\x21\xb5\x8d\xba\xd2\x31\x2b\xf5\x60\x7f\x8d\x29\x2f",
        },
        // Round 9
        AppdxBRound {
            start: *b"\xea\x83\x5c\xf0\x04\x45\x33\x2d\x65\x5d\x98\xad\x85\x96\xb0\xc5",
            after_sub_bytes: *b"\x87\xec\x4a\x8c\xf2\x6e\xc3\xd8\x4d\x4c\x46\x95\x97\x90\xe7\xa6",
            after_shift_rows: *b"\x87\x6e\x46\xa6\xf2\x4c\xe7\x8c\x4d\x90\x4a\xd8\x97\xec\xc3\x95",
            after_mix_columns: Some(
                *b"\x47\x37\x94\xed\x40\xd4\xe4\xa5\xa3\x70\x3a\xa6\x4c\x9f\x42\xbc",
            ),
            round_key: *b"\xac\x77\x66\xf3\x19\xfa\xdc\x21\x28\xd1\x29\x41\x57\x5c\x00\x6e",
        },
        // Round 10 -- the final round, which omits MixColumns().
        AppdxBRound {
            start: *b"\xeb\x40\xf2\x1e\x59\x2e\x38\x84\x8b\xa1\x13\xe7\x1b\xc3\x42\xd2",
            after_sub_bytes: *b"\xe9\x09\x89\x72\xcb\x31\x07\x5f\x3d\x32\x7d\x94\xaf\x2e\x2c\xb5",
            after_shift_rows: *b"\xe9\x31\x7d\xb5\xcb\x32\x2c\x72\x3d\x2e\x89\x5f\xaf\x09\x07\x94",
            after_mix_columns: None,
            round_key: *b"\xd0\x14\xf9\xa8\xc9\xee\x25\x89\xe1\x3f\x0c\xc8\xb6\x63\x0c\xa6",
        },
    ];

    /// Reads round key `round` out of the schedule as the 16 bytes AddRoundKey() will XOR in, ie
    /// the four words `w[4 * round + c]` laid out as the four columns of a state (Sec 3.5).
    fn round_key_bytes<const Nroundkeys: usize>(
        w: &KeySchedule<Nroundkeys>,
        round: usize,
    ) -> [u8; BLOCK_LEN] {
        let mut bytes = [0u8; BLOCK_LEN];
        for c in 0..Nb {
            let [b0, b1, b2, b3] = w[4 * round + c].to_be_bytes();
            bytes[4 * c] = b0;
            bytes[4 * c + 1] = b1;
            bytes[4 * c + 2] = b2;
            bytes[4 * c + 3] = b3;
        }
        bytes
    }

    /// Walks FIPS 197 Algorithm 1 one transformation at a time, checking the state against **every**
    /// intermediate value in the Appendix B table, and printing the whole trace.
    ///
    /// `appdx_b_cipher_example` in `tests/aes_tests.rs` already checks that the public engine produces
    /// the right ciphertext for this vector. The value of this test is that a failure names the exact
    /// round and the exact transformation that first diverged, instead of just reporting sixteen wrong
    /// bytes at the end.
    ///
    /// To see the trace, run with `--nocapture`; the test harness swallows stdout otherwise:
    ///
    /// ```text
    /// cargo test -p bouncycastle-aes appdx_b -- --nocapture
    /// ```
    #[test]
    fn appdx_b_round_trace() {
        let w = key_expansion::<AES128_KEY_LEN, AES128_Nroundkeys>(&appdx_b_key());

        // Algorithm 1 line 2: state <- in.
        let mut state = APPDX_B_PLAINTEXT;

        print_header(&state, &round_key_bytes(&w, 0), &APPDX_B_CIPHERTEXT);

        // Line 3: the initial AddRoundKey(), which the appendix folds into its "input" row; its
        // result is what the table calls round 1's "Start of Round".
        println!("Round 0 (the initial AddRoundKey of Alg 1 line 3)");
        println!("  Round Key Value  = {}", hex(&round_key_bytes(&w, 0)));
        add_round_key(&mut state, w.words(), 0);

        // Lines 4-12: Nr rounds, the last of which omits MixColumns().
        for (i, expected) in APPDX_B_ROUNDS.iter().enumerate() {
            let round = i + 1;
            println!("Round {round}");

            assert_eq!(hex(&state), hex(&expected.start), "round {round}: Start of Round");
            println!("  Start of Round   = {}", hex(&state));

            sub_bytes(&mut state); // line 5 (line 10 in the final round)
            assert_eq!(
                hex(&state),
                hex(&expected.after_sub_bytes),
                "round {round}: After SubBytes"
            );
            println!("  After SubBytes   = {}", hex(&state));

            shift_rows(&mut state); // line 6 (line 11)
            assert_eq!(
                hex(&state),
                hex(&expected.after_shift_rows),
                "round {round}: After ShiftRows"
            );
            println!("  After ShiftRows  = {}", hex(&state));

            match expected.after_mix_columns {
                Some(after_mix_columns) => {
                    mix_columns(&mut state); // line 7
                    assert_eq!(
                        hex(&state),
                        hex(&after_mix_columns),
                        "round {round}: After MixColumns"
                    );
                    println!("  After MixColumns = {}", hex(&state));
                }
                None => println!("  After MixColumns = (omitted in the final round)"),
            }

            // The round key is checked as well as printed: these are Appendix B's "Round Key Value"
            // column, which is independently the w[i] of Appendix A.1.
            let round_key = round_key_bytes(&w, round);
            assert_eq!(hex(&round_key), hex(&expected.round_key), "round {round}: Round Key Value");
            println!("  Round Key Value  = {}", hex(&round_key));

            add_round_key(&mut state, w.words(), round); // line 8 (line 12)
        }

        // Line 13: return state.
        println!("------------------------------------------------------------------");
        println!("Output           = {}", hex(&state));
        assert_eq!(hex(&state), hex(&APPDX_B_CIPHERTEXT), "the final ciphertext");
    }

    /// The Input / Key / Expected / Actual block that heads the trace, then the separator.
    ///
    /// `Actual` is computed here by the ordinary [`cipher`] entry point rather than by the traced
    /// walk below it, so the two are independent: the header says whether the cipher is right, and
    /// the trace says where it went wrong if it is not.
    fn print_header(
        input: &[u8; BLOCK_LEN],
        key: &[u8; BLOCK_LEN],
        expected_output: &[u8; BLOCK_LEN],
    ) {
        let w = key_expansion::<AES128_KEY_LEN, AES128_Nroundkeys>(&appdx_b_key());
        let mut actual = *input;
        cipher::<AES128_Nr, AES128_Nroundkeys>(&mut actual, &w);

        println!();
        println!("=== FIPS 197 Appendix B -- Cipher Example (AES-128) ===");
        println!("Input            = {}", hex(input));
        println!("Key              = {}", hex(key));
        println!("Expected Output  = {}", hex(expected_output));
        println!("Actual Output    = {}", hex(&actual));
        println!("------------------------------------------------------------------");
        println!(
            "Intermediate states, one line per transformation. Each is 16 bytes in this crate's"
        );
        println!("flat order, which is the appendix's 4x4 grid read DOWN THE COLUMNS (Eq 3.6).");
        println!();
    }

    /// Formats a state as spaced hex, in the byte order the appendix's grids read down the columns.
    fn hex(state: &[u8; BLOCK_LEN]) -> std::string::String {
        use std::fmt::Write;

        let mut out = std::string::String::with_capacity(3 * BLOCK_LEN);
        for (i, byte) in state.iter().enumerate() {
            if i != 0 {
                out.push(' ');
            }
            // Writing into a String cannot fail.
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    /// EqInvCipher() with the `dw` schedule must produce exactly what InvCipher() produces with `w`
    /// -- that is the whole claim behind the name "equivalent inverse cipher" (Sec 5.3.5), and it is
    /// the only property that matters here, since FIPS 197 publishes no separate vectors for it.
    ///
    /// Also the real test of [`key_expansion_eic`]: Algorithm 4 only inverts Algorithm 1 if the
    /// InvMixColumns() pass over the middle round keys was done correctly.
    fn check_eq_inv_cipher<const KEY_LEN: usize, const Nr: usize, const Nroundkeys: usize>(
        key: &KeyMaterial<KEY_LEN>,
        plaintext: &[u8; BLOCK_LEN],
    ) {
        let w = key_expansion::<KEY_LEN, Nroundkeys>(key);
        let dw = key_expansion_eic::<KEY_LEN, Nroundkeys>(key);

        // Algorithm 1, to have something to invert.
        let mut ciphertext = *plaintext;
        cipher::<Nr, Nroundkeys>(&mut ciphertext, &w);
        assert_ne!(&ciphertext, plaintext, "Cipher() did nothing");

        // Algorithm 3 and Algorithm 4 must both invert it, and must agree with each other.
        let mut via_inv_cipher = ciphertext;
        inv_cipher::<Nr, Nroundkeys>(&mut via_inv_cipher, &w);

        let mut via_eq_inv_cipher = ciphertext;
        eq_inv_cipher::<Nr, Nroundkeys>(&mut via_eq_inv_cipher, &dw);

        assert_eq!(&via_inv_cipher, plaintext, "InvCipher() (Algorithm 3)");
        assert_eq!(&via_eq_inv_cipher, plaintext, "EqInvCipher() (Algorithm 4)");
        assert_eq!(via_eq_inv_cipher, via_inv_cipher, "Algorithms 3 and 4 must agree");

        // There used to be a check here that EqInvCipher() with the *unmodified* schedule does not
        // decrypt correctly. It is gone because it no longer compiles: `w` is a KeySchedule and
        // eq_inv_cipher() takes a KeyScheduleEIC, so that mistake is now a type error rather than
        // something a test has to catch after the fact.
    }

    /// Algorithm 4 for AES-128, over the Appendix B vector.
    #[test]
    fn eq_inv_cipher_128() {
        check_eq_inv_cipher::<AES128_KEY_LEN, AES128_Nr, AES128_Nroundkeys>(
            &appdx_b_key(),
            &APPDX_B_PLAINTEXT,
        );
    }

    /// Algorithm 4 for AES-192. FIPS 197 has no worked example for this size, so the key and
    /// plaintext are arbitrary -- what is being checked is agreement between Algorithms 3 and 4 over
    /// the 12-round loop.
    #[test]
    fn eq_inv_cipher_192() {
        let key =
            KeyMaterial192::from_bytes_as_type(&DUMMY_SEED[1..25], KeyType::SymmetricCipherKey)
                .unwrap();
        check_eq_inv_cipher::<AES192_KEY_LEN, AES192_Nr, AES192_Nroundkeys>(
            &key, &APPDX_B_PLAINTEXT,
        );
    }

    /// Algorithm 4 for AES-256, over the 14-round loop.
    #[test]
    fn eq_inv_cipher_256() {
        let key =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[1..33], KeyType::SymmetricCipherKey)
                .unwrap();
        check_eq_inv_cipher::<AES256_KEY_LEN, AES256_Nr, AES256_Nroundkeys>(
            &key, &APPDX_B_PLAINTEXT,
        );
    }

    /// The two [`rot_word`] implementations must agree, since either may be used.
    #[test]
    fn rot_word_implementations_agree() {
        // Eq (5.10) itself: the rotation moves a0 to the end.
        assert_eq!(rot_word(0x00010203), 0x01020300);

        // A spread of words, including the degenerate ones and a value from the Appendix A.1 table
        // (at i = 4, RotWord(09cf4f3c) = cf4f3c09).
        for word in [0x00000000, 0xffffffff, 0x09cf4f3c, 0x80000001, 0x12345678] {
            assert_eq!(rot_word(word), rot_word_coreys_way(word), "word={word:#010x}");
        }
    }
}
