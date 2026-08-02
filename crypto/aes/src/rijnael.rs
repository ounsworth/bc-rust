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
