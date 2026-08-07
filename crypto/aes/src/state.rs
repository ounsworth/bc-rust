//! The four byte-oriented transformations of the AES state, and their inverses.
//!
//! | Function | FIPS 197 | Inverse | FIPS 197 |
//! |----------|----------|---------|----------|
//! | [`sub_bytes`]    | Sec 5.1.1, Eq 5.2-5.4 | [`inv_sub_bytes`]    | Sec 5.3.2 |
//! | [`shift_rows`]   | Sec 5.1.2, Eq 5.5     | [`inv_shift_rows`]   | Sec 5.3.1, Eq 5.12 |
//! | [`mix_columns`]  | Sec 5.1.3, Eq 5.7-5.8 | [`inv_mix_columns`]  | Sec 5.3.3, Eq 5.14-5.15 |
//!
//! ADDROUNDKEY() is not here because it needs the key schedule; it lives with the engine in
//! [`crate::aes`].
//!
//! # The state layout, and why it is a flat 16-byte array
//!
//! FIPS 197 Section 3.4 defines the state as a 4x4 array of bytes `s[r, c]`, filled from the input
//! block by Eq (3.6):
//!
//! ```text
//! s[r, c] = in[r + 4c]     for 0 <= r < 4 and 0 <= c < 4
//! ```
//!
//! We store the state as a flat `[u8; 16]` in exactly that order, so `state[r + 4 * c]` *is*
//! `s[r, c]`, and copying a block in or out (Eq 3.6 and 3.7) is a plain 16-byte copy with no
//! transposition. In this layout a *column* is a contiguous 4-byte run -- `state[4c .. 4c + 4]` --
//! which is what MIXCOLUMNS() and ADDROUNDKEY() operate on, and it also matches the byte order of
//! a key schedule word (Section 3.5), so those two functions stay index-free.
//!
//! The tradeoff is that a *row* is strided by 4, which only SHIFTROWS() cares about; it is written
//! out longhand below.
//!
//! Every function here takes `&mut [u8; AES_BLOCK_LEN]`, so the block length is enforced by the
//! compiler rather than checked at runtime, and none of them can fail.

/// The AES block length in bytes. Every AES variant has a 128-bit block (FIPS 197 Table 3).
pub const AES_BLOCK_LEN: usize = 16;

/// The number of columns of the state, `Nb` in FIPS 197. This Standard fixes `Nb = 4`
/// (Section 2.3); Rijndael in general allows other values, which is why the spec keeps a name for
/// it at all.
pub(crate) const NB: usize = 4;

/// SUBBYTES(): applies the S-box to each byte of the state independently (FIPS 197 Section 5.1.1).
///
/// The S-box itself is not a lookup table. It is evaluated as a bitsliced Boolean circuit in
/// [`crate::sub_bytes`], which substitutes all 16 bytes of the state in parallel and, unlike a
/// table, never indexes memory with a secret byte. See that module for the representation and
/// [`crate::sub_bytes::sub_bytes_block`] for the transformation itself.
#[inline(always)]
pub(crate) fn sub_bytes(state: &mut [u8; AES_BLOCK_LEN]) {
    // s'[r, c] = SBOX(s[r, c]). The transformation is per-byte and position-independent, so the
    // circuit's flat lane order is equivalent to the row/column form in Figure 2.
    crate::sub_bytes::sub_bytes_block(state);
}

/// INVSUBBYTES(): the inverse of [`sub_bytes`], applying INVSBOX() to each byte
/// (FIPS 197 Section 5.3.2).
#[inline(always)]
pub(crate) fn inv_sub_bytes(state: &mut [u8; AES_BLOCK_LEN]) {
    crate::sub_bytes::inv_sub_bytes_block(state);
}

/// SHIFTROWS(): cyclically shifts row `r` of the state left by `r` bytes
/// (FIPS 197 Section 5.1.2).
///
/// Eq (5.5) is `s'[r, c] = s[r, (c + r) mod 4]`. Substituting the flat layout `s[r, c] ==
/// state[r + 4c]` gives `new[r + 4c] = old[r + 4 * ((c + r) mod 4)]`, which for each row is a
/// left-rotation of that row's four (stride-4) bytes by `r` positions -- the leftward movement
/// drawn in Figure 3.
///
/// Written out per row rather than as a loop over a copy of the state, so that no second copy of
/// the state is created (see the crate docs on scrubbing intermediate state).
#[inline(always)]
pub(crate) fn shift_rows(state: &mut [u8; AES_BLOCK_LEN]) {
    // Row 0 (r = 0) is unchanged, per Eq (5.5) with r = 0.

    // Row 1: rotate [s(1,0), s(1,1), s(1,2), s(1,3)] left by 1.
    let row1_c0 = state[1];
    state[1] = state[5]; // s'(1,0) = s(1,1)
    state[5] = state[9]; // s'(1,1) = s(1,2)
    state[9] = state[13]; // s'(1,2) = s(1,3)
    state[13] = row1_c0; // s'(1,3) = s(1,0)

    // Row 2: rotate left by 2, ie swap the two halves of the row.
    let row2_c0 = state[2];
    let row2_c1 = state[6];
    state[2] = state[10]; // s'(2,0) = s(2,2)
    state[6] = state[14]; // s'(2,1) = s(2,3)
    state[10] = row2_c0; // s'(2,2) = s(2,0)
    state[14] = row2_c1; // s'(2,3) = s(2,1)

    // Row 3: rotate left by 3, which is the same as rotating right by 1.
    let row3_c3 = state[15];
    state[15] = state[11]; // s'(3,3) = s(3,2)
    state[11] = state[7]; // s'(3,2) = s(3,1)
    state[7] = state[3]; // s'(3,1) = s(3,0)
    state[3] = row3_c3; // s'(3,0) = s(3,3)
}

/// INVSHIFTROWS(): the inverse of [`shift_rows`], cyclically shifting row `r` right by `r` bytes
/// (FIPS 197 Section 5.3.1).
///
/// Eq (5.12) is `s'[r, c] = s[r, (c - r) mod 4]`; in the flat layout that is a right-rotation of
/// each row by `r`, ie the rightward movement drawn in Figure 9.
#[inline(always)]
pub(crate) fn inv_shift_rows(state: &mut [u8; AES_BLOCK_LEN]) {
    // Row 0 (r = 0) is unchanged.

    // Row 1: rotate right by 1.
    let row1_c3 = state[13];
    state[13] = state[9]; // s'(1,3) = s(1,2)
    state[9] = state[5]; // s'(1,2) = s(1,1)
    state[5] = state[1]; // s'(1,1) = s(1,0)
    state[1] = row1_c3; // s'(1,0) = s(1,3)

    // Row 2: rotate right by 2 -- identical to rotating left by 2, so this is its own inverse.
    let row2_c0 = state[2];
    let row2_c1 = state[6];
    state[2] = state[10]; // s'(2,0) = s(2,2)
    state[6] = state[14]; // s'(2,1) = s(2,3)
    state[10] = row2_c0; // s'(2,2) = s(2,0)
    state[14] = row2_c1; // s'(2,3) = s(2,1)

    // Row 3: rotate right by 3, which is the same as rotating left by 1.
    let row3_c0 = state[3];
    state[3] = state[7]; // s'(3,0) = s(3,1)
    state[7] = state[11]; // s'(3,1) = s(3,2)
    state[11] = state[15]; // s'(3,2) = s(3,3)
    state[15] = row3_c0; // s'(3,3) = s(3,0)
}

/// MIXCOLUMNS(): multiplies each column of the state by the fixed matrix of Eq (5.7)
/// (FIPS 197 Section 5.1.3).
///
/// The four output bytes of each column are Eq (5.8) transcribed literally, with the GF(2^8)
/// products supplied by the fixed multipliers at the bottom of this module:
///
/// ```text
/// s'(0,c) = ({02} . s(0,c)) + ({03} . s(1,c)) +          s(2,c)  +          s(3,c)
/// s'(1,c) =          s(0,c)  + ({02} . s(1,c)) + ({03} . s(2,c)) +          s(3,c)
/// s'(2,c) =          s(0,c)  +          s(1,c)  + ({02} . s(2,c)) + ({03} . s(3,c))
/// s'(3,c) = ({03} . s(0,c)) +          s(1,c)  +          s(2,c)  + ({02} . s(3,c))
/// ```
///
/// where `.` is GF(2^8) multiplication and `+` is XOR (Section 4.1).
#[inline(always)]
pub(crate) fn mix_columns(state: &mut [u8; AES_BLOCK_LEN]) {
    for c in 0..NB {
        // A column is contiguous in this layout: state[4c + r] == s(r, c).
        let s0 = state[4 * c];
        let s1 = state[4 * c + 1];
        let s2 = state[4 * c + 2];
        let s3 = state[4 * c + 3];

        state[4 * c] = mul_02(s0) ^ mul_03(s1) ^ s2 ^ s3;
        state[4 * c + 1] = s0 ^ mul_02(s1) ^ mul_03(s2) ^ s3;
        state[4 * c + 2] = s0 ^ s1 ^ mul_02(s2) ^ mul_03(s3);
        state[4 * c + 3] = mul_03(s0) ^ s1 ^ s2 ^ mul_02(s3);
    }
}

/// INVMIXCOLUMNS(): the inverse of [`mix_columns`], multiplying each column by the inverse matrix
/// of Eq (5.14) (FIPS 197 Section 5.3.3).
///
/// This is Eq (5.15) transcribed literally:
///
/// ```text
/// s'(0,c) = ({0e} . s(0,c)) + ({0b} . s(1,c)) + ({0d} . s(2,c)) + ({09} . s(3,c))
/// s'(1,c) = ({09} . s(0,c)) + ({0e} . s(1,c)) + ({0b} . s(2,c)) + ({0d} . s(3,c))
/// s'(2,c) = ({0d} . s(0,c)) + ({09} . s(1,c)) + ({0e} . s(2,c)) + ({0b} . s(3,c))
/// s'(3,c) = ({0b} . s(0,c)) + ({0d} . s(1,c)) + ({09} . s(2,c)) + ({0e} . s(3,c))
/// ```
#[inline(always)]
pub(crate) fn inv_mix_columns(state: &mut [u8; AES_BLOCK_LEN]) {
    for c in 0..NB {
        let s0 = state[4 * c];
        let s1 = state[4 * c + 1];
        let s2 = state[4 * c + 2];
        let s3 = state[4 * c + 3];

        state[4 * c] = mul_0e(s0) ^ mul_0b(s1) ^ mul_0d(s2) ^ mul_09(s3);
        state[4 * c + 1] = mul_09(s0) ^ mul_0e(s1) ^ mul_0b(s2) ^ mul_0d(s3);
        state[4 * c + 2] = mul_0d(s0) ^ mul_09(s1) ^ mul_0e(s2) ^ mul_0b(s3);
        state[4 * c + 3] = mul_0b(s0) ^ mul_0d(s1) ^ mul_09(s2) ^ mul_0e(s3);
    }
}

/* *** Arithmetic in GF(2^8), FIPS 197 Section 4 ***
 *
 * Every byte of the state is an element of GF(2^8); ie the polynomial (Eq 4.1):
 *
 *     b(x) = b7*x^7 + b6*x^6 + b5*x^5 + b4*x^4 + b3*x^3 + b2*x^2 + b1*x + b0
 *
 * Addition in the field is the bitwise XOR of the two bytes (Section 4.1), which needs no
 * function. Multiplication (Section 4.2) is polynomial multiplication reduced modulo the fixed
 * polynomial (Eq 4.3):
 *
 *     m(x) = x^8 + x^4 + x^3 + x + 1
 *
 * Only the six fixed multipliers below are needed, because the cipher never performs a general
 * field multiplication: MIXCOLUMNS() multiplies only by {02} and {03} (Eq 5.6), and
 * INVMIXCOLUMNS() only by {09}, {0b}, {0d} and {0e} (Eq 5.13). Each is a short chain of
 * `xtimes()` calls plus XORs, exactly as Section 4.2 suggests ("Multiplication by higher powers
 * of x ... can be implemented by the repeated application of xTimes()").
 *
 * 🚨 Security 🚨 A general multiply would need either a data-dependent loop or a log/antilog
 * table, both of which leak the multiplicand through timing or cache state. Everything below is
 * branch-free and index-free: only shifts, XORs and masks over the input byte, so neither the
 * execution time nor the memory access pattern depends on the secret value being multiplied. */

/// Multiplies `b` by {02} in GF(2^8); ie FIPS 197 Eq (4.5) xTimes(b).
///
/// The spec writes this as a conditional on the high bit of `b`:
///
/// ```text
/// xTimes(b) = {b6 b5 b4 b3 b2 b1 b0 0}                       if b7 = 0
/// xTimes(b) = {b6 b5 b4 b3 b2 b1 b0 0} XOR {0 0 0 1 1 0 1 1}  if b7 = 1
/// ```
///
/// We evaluate both arms unconditionally and select between them with a mask, so that the timing
/// and the branch-predictor state do not depend on the secret value of `b`. Do not "simplify" this
/// back into an `if`.
#[inline(always)]
const fn xtimes(b: u8) -> u8 {
    // `b >> 7` is exactly b7, so it is 0 or 1; `wrapping_neg()` maps 1 -> 0xFF and 0 -> 0x00.
    let b7_mask = (b >> 7).wrapping_neg();

    // `b << 1` is the polynomial multiplication by x. It discards b7, which is the degree-8 term
    // that the modular reduction has to remove.
    // {1b} == {0 0 0 1 1 0 1 1} is m(x) (Eq 4.3) with its x^8 term dropped, so XOR-ing it in is
    // the reduction "mod m(x)" -- and it must only happen when a degree-8 term was actually
    // produced, which is what the mask selects.
    (b << 1) ^ (b7_mask & 0x1b)
}

/// Multiplies `b` by {02}, one of the two MIXCOLUMNS() coefficients (FIPS 197 Eq 5.6).
///
/// This is just [`xtimes`] under the name used by Eq (5.8), for readability at the call site.
#[inline(always)]
const fn mul_02(b: u8) -> u8 {
    xtimes(b)
}

/// Multiplies `b` by {03}, the other MIXCOLUMNS() coefficient (FIPS 197 Eq 5.6).
///
/// {03} = {02} XOR {01} (ie x + 1), and multiplication distributes over field addition, so
/// b*{03} = xTimes(b) XOR b.
#[inline(always)]
const fn mul_03(b: u8) -> u8 {
    xtimes(b) ^ b
}

/// Multiplies `b` by {09}, an INVMIXCOLUMNS() coefficient (FIPS 197 Eq 5.13).
///
/// {09} = {08} XOR {01}, ie x^3 + 1, so b*{09} = xTimes^3(b) XOR b.
#[inline(always)]
const fn mul_09(b: u8) -> u8 {
    let x8 = xtimes(xtimes(xtimes(b)));
    x8 ^ b
}

/// Multiplies `b` by {0b}, an INVMIXCOLUMNS() coefficient (FIPS 197 Eq 5.13).
///
/// {0b} = {08} XOR {02} XOR {01}, ie x^3 + x + 1.
#[inline(always)]
const fn mul_0b(b: u8) -> u8 {
    let x2 = xtimes(b);
    let x8 = xtimes(xtimes(x2));
    x8 ^ x2 ^ b
}

/// Multiplies `b` by {0d}, an INVMIXCOLUMNS() coefficient (FIPS 197 Eq 5.13).
///
/// {0d} = {08} XOR {04} XOR {01}, ie x^3 + x^2 + 1.
#[inline(always)]
const fn mul_0d(b: u8) -> u8 {
    let x4 = xtimes(xtimes(b));
    let x8 = xtimes(x4);
    x8 ^ x4 ^ b
}

/// Multiplies `b` by {0e}, an INVMIXCOLUMNS() coefficient (FIPS 197 Eq 5.13).
///
/// {0e} = {08} XOR {04} XOR {02}, ie x^3 + x^2 + x. Note there is no XOR of `b` itself here,
/// because {0e} has no constant term.
#[inline(always)]
const fn mul_0e(b: u8) -> u8 {
    let x2 = xtimes(b);
    let x4 = xtimes(x2);
    let x8 = xtimes(x4);
    x8 ^ x4 ^ x2
}

/// A general GF(2^8) multiplication, used only to cross-check the fixed multipliers above and to
/// derive the S-box from its mathematical definition in the unit tests.
///
/// This is deliberately **not** available outside of tests: the loop below branches on the bits of
/// `b`, so it is not constant-time and must never be used on secret data.
#[cfg(test)]
pub(crate) fn gf_mul(a: u8, b: u8) -> u8 {
    let mut product = 0u8;
    let mut a_shifted = a;
    let mut b_remaining = b;

    // Section 4.2: multiply the polynomials, accumulating a*x^i for each set bit i of b, reducing
    // mod m(x) as we go (which the spec notes may be applied to intermediate steps).
    while b_remaining != 0 {
        if b_remaining & 1 == 1 {
            product ^= a_shifted;
        }
        a_shifted = xtimes(a_shifted);
        b_remaining >>= 1;
    }

    product
}

/// Raises `b` to the power `exponent` in GF(2^8) by repeated multiplication. Tests only.
#[cfg(test)]
pub(crate) fn gf_pow(b: u8, exponent: u32) -> u8 {
    let mut acc = 1u8;
    for _ in 0..exponent {
        acc = gf_mul(acc, b);
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a state from the four 32-bit words that NIST's intermediate-value files print for it.
    ///
    /// Those files print the state as `state[0..4] state[4..8] state[8..12] state[12..16]`, each
    /// group as a big-endian hex word -- ie the four *columns* of the state in order, which is the
    /// same as the flat byte order of this implementation (see the module docs).
    const fn state_of(w0: u32, w1: u32, w2: u32, w3: u32) -> [u8; AES_BLOCK_LEN] {
        let (a, b, c, d) = (w0.to_be_bytes(), w1.to_be_bytes(), w2.to_be_bytes(), w3.to_be_bytes());
        [
            a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3], c[0], c[1], c[2], c[3], d[0], d[1],
            d[2], d[3],
        ]
    }

    /* The intermediate values below are from the NIST "AES Core" ECB-AES128 intermediate value
     * file, first block: key = 2B7E1516 28AED2A6 ABF71588 09CF4F3C,
     * plaintext = 6BC1BEE2 2E409F96 E93D7E11 7393172A.
     * Round 1 and round 2 are enough to pin every transformation; the remaining rounds, and the
     * AES-192/AES-256 variants, are covered end to end by the known-answer tests in
     * tests/aes_tests.rs. */

    /// Round 1 input, ie the state after the initial ADDROUNDKEY() ("KeyAddition" in the file).
    const R1_START: [u8; AES_BLOCK_LEN] = state_of(0x40BFABF4, 0x06EE4D30, 0x42CA6B99, 0x7A5C5816);
    /// Round 1 after SUBBYTES() ("Substitution").
    const R1_SUB: [u8; AES_BLOCK_LEN] = state_of(0x090862BF, 0x6F28E304, 0x2C747FEE, 0xDA4A6A47);
    /// Round 1 after SHIFTROWS() ("ShiftRow").
    const R1_SHIFT: [u8; AES_BLOCK_LEN] = state_of(0x09287F47, 0x6F746ABF, 0x2C4A6204, 0xDA08E3EE);
    /// Round 1 after MIXCOLUMNS() ("MixColumn").
    const R1_MIX: [u8; AES_BLOCK_LEN] = state_of(0x529F16C2, 0x978615CA, 0xE01AAE54, 0xBA1A2659);

    /// Round 2 input, ie the state after round 1's ADDROUNDKEY().
    const R2_START: [u8; AES_BLOCK_LEN] = state_of(0xF265E8D5, 0x1FD2397B, 0xC3B9976D, 0x9076505C);
    /// Round 2 after SUBBYTES().
    const R2_SUB: [u8; AES_BLOCK_LEN] = state_of(0x894D9B03, 0xC0B51221, 0x2E56883C, 0x6038534A);
    /// Round 2 after SHIFTROWS().
    const R2_SHIFT: [u8; AES_BLOCK_LEN] = state_of(0x89B5884A, 0xC0565303, 0x2E389B21, 0x604D123C);
    /// Round 2 after MIXCOLUMNS().
    const R2_MIX: [u8; AES_BLOCK_LEN] = state_of(0x0F31E929, 0x319A3558, 0xAEC95893, 0x39F04D87);

    #[test]
    fn sub_bytes_matches_nist_intermediate_values() {
        let mut state = R1_START;
        sub_bytes(&mut state);
        assert_eq!(state, R1_SUB);

        let mut state = R2_START;
        sub_bytes(&mut state);
        assert_eq!(state, R2_SUB);
    }

    #[test]
    fn shift_rows_matches_nist_intermediate_values() {
        let mut state = R1_SUB;
        shift_rows(&mut state);
        assert_eq!(state, R1_SHIFT);

        let mut state = R2_SUB;
        shift_rows(&mut state);
        assert_eq!(state, R2_SHIFT);
    }

    #[test]
    fn mix_columns_matches_nist_intermediate_values() {
        let mut state = R1_SHIFT;
        mix_columns(&mut state);
        assert_eq!(state, R1_MIX);

        let mut state = R2_SHIFT;
        mix_columns(&mut state);
        assert_eq!(state, R2_MIX);
    }

    /* The inverse transformations are pinned against the same NIST values, read in the other
     * direction. (The decryption traces in those files apply INVSUBBYTES() and INVSHIFTROWS() in
     * the opposite order to Algorithm 3 -- the two commute, since one is per-byte and the other is
     * a permutation of positions -- so running the encryption values backwards is the unambiguous
     * way to pin these.) */

    #[test]
    fn inv_sub_bytes_matches_nist_intermediate_values() {
        let mut state = R1_SUB;
        inv_sub_bytes(&mut state);
        assert_eq!(state, R1_START);

        let mut state = R2_SUB;
        inv_sub_bytes(&mut state);
        assert_eq!(state, R2_START);
    }

    #[test]
    fn inv_shift_rows_matches_nist_intermediate_values() {
        let mut state = R1_SHIFT;
        inv_shift_rows(&mut state);
        assert_eq!(state, R1_SUB);

        let mut state = R2_SHIFT;
        inv_shift_rows(&mut state);
        assert_eq!(state, R2_SUB);
    }

    #[test]
    fn inv_mix_columns_matches_nist_intermediate_values() {
        let mut state = R1_MIX;
        inv_mix_columns(&mut state);
        assert_eq!(state, R1_SHIFT);

        let mut state = R2_MIX;
        inv_mix_columns(&mut state);
        assert_eq!(state, R2_SHIFT);
    }

    /// Each transformation composed with its inverse must be the identity, for a spread of states
    /// including the two degenerate ones (all-zero and all-ones) that a vector-only test set can
    /// easily miss.
    #[test]
    fn every_transformation_round_trips() {
        let mut states = [[0u8; AES_BLOCK_LEN]; 4];
        states[1] = [0xFF; AES_BLOCK_LEN];
        // A state with every byte distinct catches transposition and off-by-one row errors.
        for (i, byte) in states[2].iter_mut().enumerate() {
            *byte = i as u8;
        }
        states[3] = R1_START;

        for original in states.iter() {
            let mut state = *original;

            sub_bytes(&mut state);
            inv_sub_bytes(&mut state);
            assert_eq!(&state, original, "sub_bytes round trip");

            shift_rows(&mut state);
            inv_shift_rows(&mut state);
            assert_eq!(&state, original, "shift_rows round trip");

            mix_columns(&mut state);
            inv_mix_columns(&mut state);
            assert_eq!(&state, original, "mix_columns round trip");
        }
    }

    /// SHIFTROWS() must leave row 0 alone and must be a pure permutation of the other rows: it can
    /// neither change any byte's value nor move a byte out of its row.
    #[test]
    fn shift_rows_permutes_within_rows_only() {
        let mut state = [0u8; AES_BLOCK_LEN];
        for (i, byte) in state.iter_mut().enumerate() {
            // Encode the row in the low nibble and the column in the high nibble.
            *byte = ((i / NB) as u8) << 4 | (i % NB) as u8;
        }
        let original = state;
        shift_rows(&mut state);

        for r in 0..4 {
            for c in 0..NB {
                let moved = state[r + 4 * c];
                // The row index (low nibble here, since i % NB == r for index r + 4c) is preserved.
                assert_eq!(moved & 0x0f, (r as u8) & 0x0f, "byte left its row at ({r},{c})");
            }
        }
        // Row 0 is untouched.
        for c in 0..NB {
            assert_eq!(state[4 * c], original[4 * c], "row 0 changed at column {c}");
        }
        // And every other row genuinely moved (r = 1, 2, 3 all have non-zero shifts).
        for r in 1..4 {
            assert_ne!(
                [state[r], state[r + 4], state[r + 8], state[r + 12]],
                [original[r], original[r + 4], original[r + 8], original[r + 12]],
                "row {r} did not move"
            );
        }
    }

    /* The GF(2^8) multipliers that MIXCOLUMNS() and INVMIXCOLUMNS() are built from, pinned
     * against the worked examples in FIPS 197 Section 4 and against a general field
     * multiplication. */

    /// FIPS 197 Eq (4.6): the worked example of repeated xTimes() applied to b = {57}.
    #[test]
    fn xtimes_matches_fips197_eq_4_6() {
        assert_eq!(xtimes(0x57), 0xae); // {57} * {02}
        assert_eq!(xtimes(0xae), 0x47); // {57} * {04}
        assert_eq!(xtimes(0x47), 0x8e); // {57} * {08}
        assert_eq!(xtimes(0x8e), 0x07); // {57} * {10}
        assert_eq!(xtimes(0x07), 0x0e); // {57} * {20}
        assert_eq!(xtimes(0x0e), 0x1c); // {57} * {40}
        assert_eq!(xtimes(0x1c), 0x38); // {57} * {80}
    }

    /// FIPS 197 Eq (4.7): {57} * {13} = {57} XOR {ae} XOR {07} = {fe}.
    #[test]
    fn gf_mul_matches_fips197_eq_4_7() {
        assert_eq!(gf_mul(0x57, 0x13), 0xfe);
        // Also check the decomposition the spec uses to get there: {13} = {01} + {02} + {10}.
        assert_eq!(0x57 ^ 0xae ^ 0x07, 0xfe);
    }

    /// The fixed multipliers must agree with a general field multiplication for every input byte.
    /// This is what pins the xTimes() chains in [`mul_09`] .. [`mul_0e`] to the coefficients that
    /// FIPS 197 Eq (5.6) and Eq (5.13) actually specify.
    #[test]
    fn fixed_multipliers_match_general_multiplication() {
        for b in 0..=u8::MAX {
            assert_eq!(mul_02(b), gf_mul(b, 0x02), "mul_02({b:#04x})");
            assert_eq!(mul_03(b), gf_mul(b, 0x03), "mul_03({b:#04x})");
            assert_eq!(mul_09(b), gf_mul(b, 0x09), "mul_09({b:#04x})");
            assert_eq!(mul_0b(b), gf_mul(b, 0x0b), "mul_0b({b:#04x})");
            assert_eq!(mul_0d(b), gf_mul(b, 0x0d), "mul_0d({b:#04x})");
            assert_eq!(mul_0e(b), gf_mul(b, 0x0e), "mul_0e({b:#04x})");
        }
    }

    /// FIPS 197 Eq (4.10) and (4.11): b^254 is the multiplicative inverse of every non-zero b.
    /// This is the property that the S-box is built on, so it is worth pinning independently.
    #[test]
    fn gf_pow_254_is_the_multiplicative_inverse() {
        for b in 1..=u8::MAX {
            assert_eq!(gf_mul(b, gf_pow(b, 254)), 0x01, "inverse of {b:#04x}");
        }
    }

    /// MIXCOLUMNS() treats the four columns independently (Section 5.1.3: it "mixes their data
    /// independently of one another"), so changing one column must not disturb the others.
    #[test]
    fn mix_columns_keeps_columns_independent() {
        let mut baseline = R1_SHIFT;
        mix_columns(&mut baseline);

        for c in 0..NB {
            let mut perturbed = R1_SHIFT;
            perturbed[4 * c] ^= 0xFF;
            mix_columns(&mut perturbed);

            for other in 0..NB {
                if other == c {
                    continue;
                }
                assert_eq!(
                    perturbed[4 * other..4 * other + 4],
                    baseline[4 * other..4 * other + 4],
                    "column {c} leaked into column {other}"
                );
            }
        }
    }
}