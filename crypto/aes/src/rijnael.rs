use core::ops::{Index, IndexMut};

// TODO -- this is a convenience wrapper to make the notation state[(r,c)] work
//         but may end up having perf / mem usage impacts and therefore not be worth it.
#[derive(Clone, Copy)]
struct State([u8; 16]);

impl From<[u8; 16]> for State {
    fn from(value: [u8; 16]) -> Self {
        Self(value)
    }
}

impl Into<[u8; 16]> for State {
    fn into(self) -> [u8; 16] {
        self.0
    }
}

impl Index<(usize, usize)> for State {
    type Output = u8;

    fn index(&self, index: (usize, usize)) -> &Self::Output {
        let (r, c) = index;
        &self.0[r + 4 * c]
    }
}

impl IndexMut<(usize, usize)> for State {
    fn index_mut(&mut self, index: (usize, usize)) -> &mut Self::Output {
        let (r, c) = index;
        &mut self.0[r + 4 * c]
    }
}

// TODO -- Added constants for specific runds
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