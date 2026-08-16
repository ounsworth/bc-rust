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

    /// FIPS 197 Appendix B: [`cipher`] must turn the appendix's input into its output, and
    /// [`inv_cipher`] must turn that back into the input.
    ///
    /// This is the end-to-end check on the whole crate -- it exercises the key schedule, all four
    /// state transformations, and both algorithms of Section 5.
    #[test]
    fn appdx_b() {
        let w = key_expansion::<AES128_KEY_LEN, AES128_Nroundkeys>(&appdx_b_key());

        // Algorithm 1.
        let mut block = APPDX_B_PLAINTEXT;
        cipher::<AES128_Nr, AES128_Nroundkeys>(&mut block, &w);
        assert_eq!(block, APPDX_B_CIPHERTEXT, "Cipher() (Algorithm 1)");

        // Algorithm 3, which must invert it exactly.
        inv_cipher::<AES128_Nr, AES128_Nroundkeys>(&mut block, &w);
        assert_eq!(block, APPDX_B_PLAINTEXT, "InvCipher() (Algorithm 3)");
    }

    /// [`add_round_key`] on its own, against Appendix B's round 1 "Start of Round" state.
    ///
    /// Worth pinning separately from [`appdx_b`]: this is the one transformation that has to index
    /// into the key schedule, and a version that XORed a single word into all four columns -- rather
    /// than the four distinct words `w[4 * round + c]` -- would still be its own inverse, and so
    /// would pass any test that only checks that decryption undoes encryption.
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
