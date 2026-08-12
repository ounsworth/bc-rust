//! This file implements section 5.1.1 of FIPS 197, which includes the SBox() and SubBytes() functions.
//!
//! As presented it FIPS 197, `SBox(b: u8) -> u8` performs substitutition on a single byte, and
//! `SubBytes(state: [u8; 16]) -> [u8; 16]` acts on a 16 byte state.
//!
//! This implementation performs several optimizations based on a software implementation of the
//! Boyar-Peralta-Calik AES S-box circuit.
//!  See: <http://www.cs.yale.edu/homes/peralta/CircuitStuff/SLP_AES_113.txt>
//!
//! The main features are:
//! The circuit implementation uses exclusively AND, XOR, and XNOR and contains no branching or lookups,
//! which is as close to a constant-time implementation as software can get.
//!
//! The 16 bytes of the AES state are "bit sliced" (essentially, transposed) into 8 16-bit wide "planes" such that
//! `plane[i]` holds the `i`th bit from each of the 16 input bytes. This allows for efficient processing because,
//! for example, `plane[i] ^ plane[j]` computes the XOR of `i`th and `j`th bits of all input bytes
//! in a single XOR operation, essentially performing the SBox() operation for all bytes in the state
//! in a single operation. Essentially, we compute the SBox() for all 16 bytes of the state for the
//! cost of computing one -- minus the cost of converting the state into and out of the transposed
//! "bitsliced" representation.
//!
//! One minor consequence of this is that computation of the key schedule requires performing SBox()
//! on single byte at a time, which requires a slightly clunky conversion of creating a "state" which
//! is mostly zeroes, and processing that through sub_bytes().
//!
//! # Naming convention
//! This code handles the AES state both in its normal representation as per FIPS 197 s. 3.4, which
//! is as a `[u8; 16]`, and in its bitsliced representation `[u16; 8]`.
//! To help keep these straight, we use the type aliases
//!
//! `type State = [u8; 16];'
//! `type BitslicedState = [u16; 8];'
//!
//! and all functions that act on a BitslicedState are suffixed with `_bitsliced`.

use crate::aes::BLOCK_LEN;

/// A type to mark an AES State, as described in FIPS 197 s. 3.4.
// todo -- should this be moved to state.rs?
pub(crate) type State = [u8; BLOCK_LEN];

/// A type to mark when an AES State (`[u8; 16]`) has been transposed into its bitsliced [u16; 8] representation.
pub(crate) type BitslicedState = [u16; 8];

/// Eqn (5.11): `SubWord([a0, a1, a2, a3]) = [SBox(a0), SBox(a1), SBox(a2), SBox(a3)]`.
/// Perform the SBox on a single 4-byte word.
///
/// Note: this is only used by the KeySchedule, which only operates forward,
///       so we don't need an inv_sub_word.
pub(crate) fn sub_word(word: u32) -> u32 {
    // Since the implementation of sub_bytes() is based on the Boyar-Peralta-Calik `SLP_AES_113` circuit,
    // it acts on a whole 16-byte (4-word) state and not on a single word.
    // So, load the word we want to process into the first 4 bytes and leave the rest of the state as 0.
    let mut state: State = [0u8; 16];
    state[0..4].copy_from_slice(&word.to_be_bytes());

    // TODO --  Optimization point:
    //          Here we're handing sub_bytes() a state where only the first 4 bytes contain data
    //          and the last 12 bytes are all 0's;
    //          so the call to bitslice() will spend effort moving those 0's around.
    //          We could get a slight perf gain on the key_schedule by implementing a
    //          `bitslice_word()` and inv_bitslice_word() that only bitslices the first 4 bytes.
    //          Though the perf gain is probably negligible. Do it against perf benchmarks to see the difference.

    sub_bytes(&mut state);

    u32::from_be_bytes(state[0..4].try_into().unwrap())
}

/// SubBytes(): applies the AES S-box to every byte of one AES block (FIPS 197 Section 5.1.1).
///
/// Transposes the block into bit planes, evaluates the S-box circuit on all 16 lanes at once,
/// and transposes the result back.
///
/// This is the complete transformation of FIPS 197 Table 4.
///
/// `state` is both in input and output variable: the substituted state will be placed back
///         into the input array.
#[inline]
pub(crate) fn sub_bytes(state: &mut State) {
    let mut bitsliced_state = bitslice(state);

    sub_bytes_bitsliced(&mut bitsliced_state);
    // The circuit leaves four outputs inverted; see `sub_bytes_nots` for why this comes after.
    // TODO -- is it actually necessary to have this broken out as a separate function?
    //         Is there some reason that we can't fold this into the sub_bytes_bitsliced() / inv_sub_bytes_bitsliced() functions?
    sub_bytes_nots_bitsliced(&mut bitsliced_state);

    unbitslice(&bitsliced_state, state);
}

/// InvSubBbytes(): applies the inverse AES S-box to every byte of one AES block
/// (FIPS 197 Section 5.3.2).
///
/// The exact inverse of [`sub_bytes`].
///
/// `state` is both in input and output variable: the substituted state will be placed back
///         into the input array.
// TODO -- unit test this function by feeding in 16 bytes of Table 4 and making sure that it comes back as
//         `[0x00, 0x01, 0x02, .., 0xfe, 0xff]`. (put those unit tests in this file since this is not
//         a pub fn, so can't be tested from outside)
#[inline]
pub(crate) fn inv_sub_bytes(state: &mut State) {
    let mut bitsliced_state = bitslice(state);

    sub_bytes_nots_bitsliced(&mut bitsliced_state);

    // Note the order: the complements come **first** here since we have to undo `sub_bites` in reverse order.
    inv_sub_bytes_bitsliced(&mut bitsliced_state);

    unbitslice(&bitsliced_state, state);
}

/// Transposes one AES block into the eight bit-planes the S-box circuit operates on.
/// See [sub_bytes_bitsliced] for a full explanation.
// TODO -- this allocates a new array and returns it, while [unbitslice] works on a mut output array.
//         Is there a reason for that difference? If so, explain it, if not, make them the same.
fn bitslice(block: &State) -> BitslicedState {
    let mut planes = BitslicedState::default();

    for (lane, &byte) in block.iter().enumerate() {
        for (p, plane) in planes.iter_mut().enumerate() {
            let bit = (byte >> p) & 1;
            *plane |= u16::from(bit) << lane;
        }
    }

    planes
}

/// Transposes eight bit planes back into one AES block; the exact inverse of [`bitslice`].
fn unbitslice(planes: &BitslicedState, block: &mut State) {
    for (lane, byte) in block.iter_mut().enumerate() {
        let mut value = 0u8;
        for (p, &plane) in planes.iter().enumerate() {
            let bit = ((plane >> lane) & 1) as u8;
            value |= bit << p;
        }
        *byte = value;
    }
}

/// Applies the forward AES S-box to all 16 byte lanes of one bitsliced AES block simultaneously.
///
/// This implementation differs significantly from FIPS 197 since it is the bitsliced AES S-box
/// based on the Boyar-Peralta-Calik `SLP_AES_113` Boolean circuit.
///  See: <http://www.cs.yale.edu/homes/peralta/CircuitStuff/SLP_AES_113.txt>
///   TODO -- this file is only the bare implementation of the SBox circuit.
///           Surely somewhere there is a proper academic paper we could cite that actually describes
///           this thing with diagrams and stuff.
///
/// # Bitsliced state representation
///
/// FIPS 197 describes the AES State (often called a Block) as 16 bytes with a row-column indexing scheme.
/// This is typically held in memory as  `state: [u8; 16]`, encapsulated by the [State] type alias.
/// However, since FIPS 197 section 5.1.1 describes the SBox as as affine transformation acting
/// independently on each _bit_ of the state, it is rather inefficient to process the SBox independently
/// for each of the 16 bytes.
///
/// This is the beauty of the the Boyar-Peralta-Calik `SLP_AES_113` Boolean circuit:
/// First, we observe that SubBytes() applies independently to all 16 bytes of the state, so this can be
/// parallelized.
/// Second, if you first transpose the state into a `[u16; 8]` (thought of as 8 "planes of bits"
/// which are each 16 "lanes" wide), encapsulated in this implementation by the [BitslicedState] type
/// alias, then, for example, `plane[i] ^ plane[j]` performs the XOR of the `i`th and `j`th bits
/// for all 16 input bytes at the same time, in a single XOR operation; essentially giving a 16x speedup
/// on applying the SBox to the state.
///
/// # Circuit implementation
///
/// The Boyar-Peralta-Calik `SLP_AES_113` Boolean circuit has the following composition:
///
///```text
///     8 Boolean inputs:   U0 ... U7
///     8 Boolean outputs:  S0 ... S7
///
///     113 Boolean gates total:
///       32 AND
///       77 XOR
///        4 XNOR
///```
///
/// Thus every XOR or AND below corresponds to one Boolean gate from the S-box circuit,
/// evaluated across all 16 lanes in parallel.
///
/// An annotated version of this function is available in `docs/sub_bytes_annotated.txt`.
///
/// # 🚨 This is not the whole S-box 🚨
/// TODO -- why?
///         The paragraph below is telling me that this implementation does a weird thing.
///         It's not telling me why that weird is necessary.
///         Wouldn't it be simpler to fold those 4 NOTs into this function, and then we don't
///         need to carry this weird thing all over the file?
///         (If we do that, we'll need to leave an inline comment explaining that this differs
///          from SLP_AES_113.txt)
///
/// TODO --  Also, I want to reserve the police light emoji for actual security considerations,
///          like, you'll leak your private key if you don't pay attention to this, which this section is not.
///
/// Four bitwise complements belonging to this formulation of the forward S-box are
/// separated out into [`sub_bytes_nots_bitsliced`], which must be applied to the *output* of this
/// function to obtain the S-box of FIPS 197 Table 4. Callers who do not have a reason to
/// keep the two apart should use [`sub_bytes`], which cannot be misused this way.
fn sub_bytes_bitsliced(bitsliced_state: &mut BitslicedState) {
    // Load the eight input bit planes.
    // Note that the SLP circuit indexes bits inverse to FIPS 197: it uses `U7, U6, .., U0` where
    // FIPS 197 labels the same bits as `b0, b1, .., b7`.
    let u7 = bitsliced_state[0];
    let u6 = bitsliced_state[1];
    let u5 = bitsliced_state[2];
    let u4 = bitsliced_state[3];
    let u3 = bitsliced_state[4];
    let u2 = bitsliced_state[5];
    let u1 = bitsliced_state[6];
    let u0 = bitsliced_state[7];

    // TODO --  this is using the `let` keyword 113 times. We should put some thought into the memory
    //          footprint of this. Is it actually using 113 * u16 = 226 bytes of stack?
    //          I'm sure if we stared at this, we could find some optimization, like maybe s7 .. s0
    //          don't need to be allocated and we could write those directly into bitsliced_state[i].
    //          That said, this might be a case where the rust compiler is smarter than me.
    //          so maybe we should hold off on any attempt to further optimize this untel we have
    //          a working implementation with proper memory benches so we can actually measure if
    //          further optimization is helping or not.

    let y14 = u3 ^ u5;
    let y13 = u0 ^ u6;
    let y12 = y13 ^ y14;
    let t1 = u4 ^ y12;
    let y15 = t1 ^ u5;
    let t2 = y12 & y15;
    let y6 = y15 ^ u7;
    let y20 = t1 ^ u1;
    let y9 = u0 ^ u3;
    let y11 = y20 ^ y9;
    let t12 = y9 & y11;
    let y7 = u7 ^ y11;
    let y8 = u0 ^ u5;
    let t0 = u1 ^ u2;
    let y10 = y15 ^ t0;
    let y17 = y10 ^ y11;
    let t13 = y14 & y17;
    let t14 = t13 ^ t12;
    let y19 = y10 ^ y8;
    let t15 = y8 & y10;
    let t16 = t15 ^ t12;
    let y16 = t0 ^ y11;
    let y21 = y13 ^ y16;
    let t7 = y13 & y16;
    let y18 = u0 ^ y16;
    let y1 = t0 ^ u7;
    let y4 = y1 ^ u3;
    let t5 = y4 & u7;
    let t6 = t5 ^ t2;
    let t18 = t6 ^ t16;
    let t22 = t18 ^ y19;
    let y2 = y1 ^ u0;
    let t10 = y2 & y7;
    let t11 = t10 ^ t7;
    let t20 = t11 ^ t16;
    let t24 = t20 ^ y18;
    let y5 = y1 ^ u6;
    let t8 = y5 & y1;
    let t9 = t8 ^ t7;
    let t19 = t9 ^ t14;
    let t23 = t19 ^ y21;
    let y3 = y5 ^ y8;
    let t3 = y3 & y6;
    let t4 = t3 ^ t2;
    let t17 = t4 ^ y20;
    let t21 = t17 ^ t14;
    let t26 = t21 & t23;
    let t27 = t24 ^ t26;
    let t31 = t22 ^ t26;
    let t25 = t21 ^ t22;
    let t28 = t25 & t27;
    let t29 = t28 ^ t22;
    let z14 = t29 & y2;
    let z5 = t29 & y7;
    let t30 = t23 ^ t24;
    let t32 = t31 & t30;
    let t33 = t32 ^ t24;
    let t35 = t27 ^ t33;
    let t36 = t24 & t35;
    let t38 = t27 ^ t36;
    let t39 = t29 & t38;
    let t40 = t25 ^ t39;
    let t43 = t29 ^ t40;
    let z3 = t43 & y16;
    let tc12 = z3 ^ z5;
    let z12 = t43 & y13;
    let z13 = t40 & y5;
    let z4 = t40 & y1;
    let tc6 = z3 ^ z4;
    let t34 = t23 ^ t33;
    let t37 = t36 ^ t34;
    let t41 = t40 ^ t37;
    let z8 = t41 & y10;
    let z17 = t41 & y8;
    let t44 = t33 ^ t37;
    let z0 = t44 & y15;
    let z9 = t44 & y12;
    let z10 = t37 & y3;
    let z1 = t37 & y6;
    let tc5 = z1 ^ z0;
    let tc11 = tc6 ^ tc5;
    let z11 = t33 & y4;
    let t42 = t29 ^ t33;
    let t45 = t42 ^ t41;
    let z7 = t45 & y17;
    let tc8 = z7 ^ tc6;
    let z16 = t45 & y14;
    let z6 = t42 & y11;
    let tc16 = z6 ^ tc8;
    let z15 = t42 & y9;
    let tc20 = z15 ^ tc16;
    let tc1 = z15 ^ z16;
    let tc2 = z10 ^ tc1;
    let tc21 = tc2 ^ z11;
    let tc3 = z9 ^ tc2;
    let s0 = tc3 ^ tc16;
    let s3 = tc3 ^ tc11;
    let s1 = s3 ^ tc16;
    let tc13 = z13 ^ tc1;
    let z2 = t33 & u7;
    let tc4 = z0 ^ z2;
    let tc7 = z12 ^ tc4;
    let tc9 = z8 ^ tc7;
    let tc10 = tc8 ^ tc9;
    let tc17 = z14 ^ tc10;
    let s5 = tc21 ^ tc17;
    let tc26 = tc17 ^ tc20;
    let s2 = tc26 ^ z17;
    let tc14 = tc4 ^ tc12;
    let tc18 = tc13 ^ tc14;
    let s6 = tc10 ^ tc18;
    let s7 = z12 ^ tc18;
    let s4 = tc14 ^ s3;

    bitsliced_state[0] = s7;
    bitsliced_state[1] = s6;
    bitsliced_state[2] = s5;
    bitsliced_state[3] = s4;
    bitsliced_state[4] = s3;
    bitsliced_state[5] = s2;
    bitsliced_state[6] = s1;
    bitsliced_state[7] = s0;
}

/// Perform the four XNOR operations that are omitted from [`sub_bytes_bitsliced`] and [`inv_sub_bitys_bitsliced`].
// TODO --  why?
//          Can we just fold these in to [`sub_bytes_bitsliced`] and [`inv_sub_bitys_bitsliced`] ??
pub(crate) fn sub_bytes_nots_bitsliced(bitsliced_state: &mut BitslicedState) {
    // Each XOR applies to the 16 lanes simultaneously.
    bitsliced_state[0] ^= 0xFFFF;
    bitsliced_state[1] ^= 0xFFFF;
    bitsliced_state[5] ^= 0xFFFF;
    bitsliced_state[6] ^= 0xFFFF;
}

/// Applies the inverse AES S-box to all 16 byte lanes of one AES block simultaneously.
/// Inverse of [`sub_bytes_bitsliced`].
///
/// An annotated version of this function is available in `docs/sub_bytes_annotated.txt`.
fn inv_sub_bytes_bitsliced(bitslices_state: &mut BitslicedState) {
    // Load the eight input bit planes.
    // Note that the SLP circuit indexes bits inverse to FIPS 197: it uses `U7, U6, .., U0` where
    // FIPS 197 labels the same bits as `b0, b1, .., b7`.
    let u7 = bitslices_state[0];
    let u6 = bitslices_state[1];
    let u5 = bitslices_state[2];
    let u4 = bitslices_state[3];
    let u3 = bitslices_state[4];
    let u2 = bitslices_state[5];
    let u1 = bitslices_state[6];
    let u0 = bitslices_state[7];

    let t23 = u0 ^ u3;
    let t8 = u1 ^ t23;
    let m2 = t23 & t8;
    let t4 = u4 ^ t8;
    let t22 = u1 ^ u3;
    let t2 = u0 ^ u1;
    let t1 = u3 ^ u4;
    let t9 = u7 ^ t1;
    let m7 = t22 & t9;
    let t24 = u4 ^ u7;
    let t10 = t2 ^ t24;
    let m14 = t2 & t10;
    let r5 = u6 ^ u7;
    let t3 = t1 ^ r5;
    let t13 = t2 ^ r5;
    let t19 = t22 ^ r5;
    let t17 = u2 ^ t19;
    let t25 = u2 ^ t1;
    let r13 = u1 ^ u6;
    let t20 = t24 ^ r13;
    let m9 = t20 & t17;
    let r17 = u2 ^ u5;
    let t6 = t22 ^ r17;
    let m1 = t13 & t6;
    let y5 = u0 ^ r17;
    let m4 = t19 & y5;
    let m5 = m4 ^ m1;
    let m17 = m5 ^ t24;
    let r18 = u5 ^ u6;
    let t27 = t1 ^ r18;
    let t15 = t10 ^ t27;
    let m11 = t1 & t15;
    let m15 = m14 ^ m11;
    let m21 = m17 ^ m15;
    let m12 = t4 & t27;
    let m13 = m12 ^ m11;
    let t14 = t10 ^ r18;
    let m3 = t14 ^ m1;
    let m16 = m3 ^ m2;
    let m20 = m16 ^ m13;
    let r19 = u2 ^ u4;
    let t16 = r13 ^ r19;
    let t26 = t3 ^ t16;
    let m6 = t3 & t16;
    let m8 = t26 ^ m6;
    let m18 = m8 ^ m7;
    let m22 = m18 ^ m13;
    let m25 = m22 & m20;
    let m26 = m21 ^ m25;
    let m10 = m9 ^ m6;
    let m19 = m10 ^ m15;
    let m23 = m19 ^ t25;
    let m28 = m23 ^ m25;
    let m24 = m22 ^ m23;
    let m30 = m26 & m24;
    let m39 = m23 ^ m30;
    let m48 = m39 & y5;
    let m57 = m39 & t19;
    let m36 = m24 ^ m25;
    let m31 = m20 & m23;
    let m27 = m20 ^ m21;
    let m32 = m27 & m31;
    let m29 = m28 & m27;
    let m37 = m21 ^ m29;
    let m42 = m37 ^ m39;
    let m52 = m42 & t15;
    let m61 = m42 & t1;
    let p0 = m52 ^ m61;
    let p16 = m57 ^ m61;
    let m60 = m37 & t20;
    let m51 = m37 & t17;
    let m33 = m27 ^ m25;
    let m38 = m32 ^ m33;
    let m43 = m37 ^ m38;
    let m49 = m43 & t16;
    let p6 = m49 ^ m60;
    let p13 = m49 ^ m51;
    let m58 = m43 & t3;
    let m50 = m38 & t9;
    let m59 = m38 & t22;
    let p1 = m58 ^ m59;
    let p7 = p0 ^ p1;
    let m34 = m21 & m22;
    let m35 = m24 & m34;
    let m40 = m35 ^ m36;
    let m41 = m38 ^ m40;
    let m45 = m42 ^ m41;
    let m53 = m45 & t27;
    let p8 = m50 ^ m53;
    let p23 = p7 ^ p8;
    let m62 = m45 & t4;
    let p14 = m49 ^ m62;
    let s6 = p14 ^ p23;
    let m54 = m41 & t10;
    let p2 = m54 ^ m62;
    let p22 = p2 ^ p7;
    let s0 = p13 ^ p22;
    let p17 = m58 ^ p2;
    let p15 = m54 ^ m59;
    let m63 = m41 & t2;
    let m44 = m39 ^ m40;
    let m46 = m44 & t6;
    let p5 = m46 ^ m51;
    let p18 = m63 ^ p5;
    let p24 = p5 ^ p7;
    let p12 = m46 ^ m48;
    let s3 = p12 ^ p22;
    let m55 = m44 & t13;
    let p9 = m55 ^ m63;
    let s7 = p9 ^ p16;
    let m47 = m40 & t8;
    let p3 = m47 ^ m50;
    let p19 = p2 ^ p3;
    let s5 = p19 ^ p24;
    let p11 = p0 ^ p3;
    let p26 = p9 ^ p11;
    let m56 = m40 & t23;
    let p4 = m48 ^ m56;
    let p20 = p4 ^ p6;
    let p29 = p15 ^ p20;
    let s1 = p26 ^ p29;
    let p10 = m57 ^ p4;
    let p27 = p10 ^ p18;
    let s4 = p23 ^ p27;
    let p25 = p6 ^ p10;
    let p28 = p11 ^ p25;
    let s2 = p17 ^ p28;

    bitslices_state[0] = s7;
    bitslices_state[1] = s6;
    bitslices_state[2] = s5;
    bitslices_state[3] = s4;
    bitslices_state[4] = s3;
    bitslices_state[5] = s2;
    bitslices_state[6] = s1;
    bitslices_state[7] = s0;
}

/// Test the constructs in this file that are crate-internal and therefore not testable from
/// the external unit tests.
#[cfg(test)]
mod sbox_tests {
    use super::*;
    use bouncycastle_core_test_framework::DUMMY_SEED;

    /// A lookup table would be bad for the production code since it's not constant-time,
    /// but perfectly fine for comparing against in correctness tests.
    ///
    /// Usage: `sbox_lookup_table[i] -> SBox(i)`
    ///
    /// Note: rustfmt has messed up the formatting by line-wrapping it one column earlier than it is
    /// presented in FIPS 197.
    const sbox_lookup_table: [u8; 256] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
        0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
        0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
        0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
        0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
        0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
        0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
        0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
        0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
        0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
        0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
        0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
        0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
        0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
        0x16,
    ];

    const inv_sbox_lookup_table: [u8; 256] = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7,
        0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde,
        0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42,
        0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
        0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c,
        0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15,
        0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7,
        0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
        0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc,
        0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad,
        0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d,
        0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
        0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8,
        0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51,
        0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0,
        0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c,
        0x7d,
    ];

    // /// Utility code to generate the inverse SBox table
    // /// Note: to run this, you'll need to temporarily un-comment the #![no_std] in the lib.rs.
    // #[test]
    // fn compute_inv_sbox() {
    //     // generate the inverse sbox lookup table
    //     print!("[");
    //     for i in 0..256_usize {
    //         if i != 0 {
    //             print!(" ")
    //         }
    //         // go find it in the sbox_lookup_table
    //         for j in 0..256_usize {
    //             if i as u8 == sbox_lookup_table[j] {
    //                 print!("{:#04x},", j);
    //             }
    //         }
    //     }
    //     print!("]");
    // }

    /// This is not testing the code; just checking that there isn't a typo in the lookup tables.
    #[test]
    fn check_lookup_tables() {
        for i in 0..256_usize {
            assert_eq!(sbox_lookup_table[inv_sbox_lookup_table[i] as usize], i as u8);
        }
    }

    /// Test that [sub_bytes] produces the correct output for all 256 possible inputs, according
    /// to Table 4 in FIPS 197 section 5.1.1
    #[test]
    fn test_sub_bytes() {
        // The `sub_bytes()` function takes 16 bytes, so we'll need to invoke it 16 times to test
        // all 256 possible input values.
        for i in 0..16_usize {
            // DUMMY_SEED holds [0x00, 0x01, ..] so that i == DUMMY_SEED[i]
            let mut state: State = DUMMY_SEED[i..(i + 16)].try_into().unwrap();

            // sub_bytes produces the expected result with respect to the forward sbox
            sub_bytes(&mut state);
            assert_eq!(state, sbox_lookup_table[i..(i + 16)]);

            // and then running it through the inverse direction gives you back the original
            inv_sub_bytes(&mut state);
            assert_eq!(state, DUMMY_SEED[i..(i + 16)]);

            // and also test it in the opposite direction
            inv_sub_bytes(&mut state);
            assert_eq!(state, inv_sbox_lookup_table[i..(i + 16)]);
            sub_bytes(&mut state);
            assert_eq!(state, DUMMY_SEED[i..(i + 16)]);

            // and that's it, that's an exhaustive test of correctness.
        }
    }

    #[test]
    fn test_sub_word() {
        // Simple test that sub_word does what's expected.
        let input = u32::from_be_bytes([0x00, 0x01, 0x02, 0x03]);
        let expected_output = u32::from_be_bytes(sbox_lookup_table[0..4].try_into().unwrap());
        let output = sub_word(input);
        assert_eq!(output, expected_output);
    }
}
