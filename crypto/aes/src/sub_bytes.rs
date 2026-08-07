//! Bitsliced AES S-box implementation.
//!
//! # What this file is implementing
//!
//! FIPS 197 Section 5.1.1 defines `SUBBYTES()` as the non-linear transformation used by
//! the forward AES cipher. AES always operates on a 128-bit block, represented by FIPS 197
//! as a 4x4 matrix of 16 bytes. `SUBBYTES()` applies the AES S-box independently to each
//! of those 16 bytes.
//!
//! Conceptually, for one byte:
//!
//! ```text
//!     input byte
//!
//!     u7 u6 u5 u4 u3 u2 u1 u0
//!      |  |  |  |  |  |  |  |
//!      +--+--+--+--+--+--+--+
//!                 |
//!              AES S-box
//!                 |
//!      +--+--+--+--+--+--+--+
//!      |  |  |  |  |  |  |  |
//!     s7 s6 s5 s4 s3 s2 s1 s0
//!
//!     output byte
//! ```
//!
//! The AES S-box can be implemented in several ways. A simple implementation could use
//! FIPS 197's 256-entry S-box lookup table. This implementation instead computes the same
//! transformation as a Boolean circuit made from XOR, AND, and NOT operations.
//!
//! The forward circuit below is based on the Boyar-Peralta-Calik AES S-box circuit,
//! represented by NIST's `SLP_AES_113` straight-line program. The SLP has:
//!
//! ```text
//!     8 Boolean inputs:   U0 ... U7
//!     8 Boolean outputs:  S0 ... S7
//!
//!     113 Boolean gates total:
//!       32 AND
//!       77 XOR
//!        4 XNOR
//! ```
//!
//! The variables in `sub_bytes()` deliberately retain names such as `u7`, `y14`, `t26`,
//! `z12`, `tc18`, and `s5` because they correspond directly to intermediate wires in that
//! Boolean circuit. They are not meaningful AES concepts individually; they are temporary
//! signals used to evaluate the optimized S-box circuit.
//!
//! # Why are the inputs `u16` if an AES S-box takes bits?
//!
//! This is the most important part of understanding this file.
//!
//! In the mathematical SLP, `U0`, `U1`, ..., `U7` are each ONE Boolean bit belonging to
//! ONE byte.
//!
//! A literal scalar implementation could therefore evaluate the circuit using eight
//! individual Boolean values:
//!
//! ```text
//!     U7 = bit 7 of one byte
//!     U6 = bit 6 of one byte
//!     ...
//!     U0 = bit 0 of one byte
//! ```
//!
//! This implementation does something more efficient: it is BITSLICED.
//!
//! Instead of placing all eight bits of one byte next to one another in a normal integer,
//! bitslicing transposes a collection of bytes. Each machine word contains ONE PARTICULAR
//! BIT POSITION from MANY independent bytes.
//!
//! For example, imagine four bytes:
//!
//! ```text
//!              bit 7 6 5 4 3 2 1 0
//!
//!     byte 0      a7 a6 a5 a4 a3 a2 a1 a0
//!     byte 1      b7 b6 b5 b4 b3 b2 b1 b0
//!     byte 2      c7 c6 c5 c4 c3 c2 c1 c0
//!     byte 3      d7 d6 d5 d4 d3 d2 d1 d0
//! ```
//!
//! A bitsliced representation conceptually transposes that matrix, one plane per bit
//! position:
//!
//! ```text
//!     plane for bit 7 = [a7 b7 c7 d7]
//!     plane for bit 6 = [a6 b6 c6 d6]
//!     plane for bit 5 = [a5 b5 c5 d5]
//!     ...
//!     plane for bit 0 = [a0 b0 c0 d0]
//! ```
//!
//! This implementation uses a `u16` for every row of that transposed representation, one
//! lane per byte of a single AES block. Consequently each word has 16 independent Boolean
//! lanes:
//!
//! ```text
//!                   16 byte positions of one AES block
//!
//!                   lane 15 ... lane 2 lane 1 lane 0
//!
//!     planes[0] = u7   b0      ...   b0     b0     b0
//!     planes[1] = u6   b1      ...   b1     b1     b1
//!     planes[2] = u5   b2      ...   b2     b2     b2
//!     planes[3] = u4   b3      ...   b3     b3     b3
//!     planes[4] = u3   b4      ...   b4     b4     b4
//!     planes[5] = u2   b5      ...   b5     b5     b5
//!     planes[6] = u1   b6      ...   b6     b6     b6
//!     planes[7] = u0   b7      ...   b7     b7     b7
//!
//!                        |                  |
//!                        | one vertical     |
//!                        | column is one    |
//!                        | AES state byte   |
//! ```
//!
//! **Read that middle column carefully:** `planes[0]` holds the SLP's `U7`, which is FIPS 197's
//! `b0` -- the *least* significant bit. The two documents number bits in opposite directions,
//! and getting it backwards silently computes a bit-reversed S-box. [`bitslice`] documents the
//! trap in full, and the module's tests pin it.
//!
//! Therefore:
//!
//! ```text
//!     8 u16 words
//!       = 8 bit planes
//!
//!     each plane
//!       = 16 independent bits
//!
//!     8 planes x 16 lanes
//!       = 16 independent 8-bit values
//!       = one 128-bit AES block
//! ```
//!
//! The representation is exactly the same size as the thing it represents:
//!
//! ```text
//!     8 * 16 = 128 bits = 16 bytes
//! ```
//!
//! which is precisely the AES block of FIPS 197 Table 3. A `[u16; 8]` is therefore nothing
//! more exotic than a transposed AES state: the same 128 bits, read down the columns instead
//! of along the rows. Lane `i` is state byte `i` in the flat layout that
//! [`crate::state`] documents, so the bitsliced form drops straight into the byte-oriented
//! `CIPHER()` of [`crate::rijnael`] with no change to the surrounding engine.
//!
//! # Widening this to process several blocks at once
//!
//! Nothing in the circuit below depends on the width of the word: the 113 gates are built
//! only from `^` and `&`, with no shifts, rotates or masks. Changing `u16` to `u32` or `u64`
//! therefore turns this into a 2-block or 4-block implementation for free, and the only edits
//! required are the signatures, the transposition helpers, and the four all-ones constants in
//! [`sub_bytes_nots`]. The circuit text itself would not move a character.
//!
//! That is a worthwhile optimization, but it is not free at the call site: a wider word only
//! pays off if the *caller* has several blocks in hand at once, which means the mode of
//! operation (CTR, GCM, ...) has to be written to hand them over in batches. Until then, `u16`
//! is the honest width: it wastes no lanes on a single-block cipher.
//!
//! # Why a single XOR or AND performs 16 S-box gates
//!
//! Consider one gate from the original straight-line program:
//!
//! ```text
//!     y14 = U3 XOR U5
//! ```
//!
//! In a scalar implementation that is ONE XOR gate for ONE S-box invocation.
//!
//! Here:
//!
//! ```rust,ignore
//! let y14 = u3 ^ u5;
//! ```
//!
//! `u3` and `u5` are `u16`s. Rust's `^` operates bit-by-bit across the whole word, so
//! this performs:
//!
//! ```text
//!     y14[0]  = u3[0]  XOR u5[0]
//!     y14[1]  = u3[1]  XOR u5[1]
//!     ...
//!     y14[15] = u3[15] XOR u5[15]
//! ```
//!
//! In other words, ONE machine-word XOR evaluates that Boolean gate for all 16 S-box
//! invocations simultaneously -- ie for every byte of the AES state at once.
//!
//! The same applies to AND:
//!
//! ```rust,ignore
//! let t2 = y12 & y15;
//! ```
//!
//! which means:
//!
//! ```text
//!     t2[i] = y12[i] AND y15[i]
//!
//!     for every lane i = 0..15 simultaneously.
//! ```
//!
//! That is the central performance trick behind this implementation.
//!
//! # Why bitslicing is useful for AES
//!
//! A conventional software AES S-box implementation might perform a secret-dependent
//! lookup into a 256-byte table:
//!
//! ```text
//!     output = SBOX[input]
//! ```
//!
//! Historically, table-based implementations can create cache-timing concerns because
//! the memory address accessed depends on secret-derived data.
//!
//! A bitsliced Boolean circuit instead computes the S-box using fixed sequences of
//! ordinary logical instructions:
//!
//! ```text
//!     XOR
//!     AND
//!     NOT / XNOR
//! ```
//!
//! There is no secret-selected S-box memory entry. The instruction sequence is determined
//! by the circuit rather than by the input value. In addition, each machine instruction
//! evaluates the corresponding Boolean gate across 16 independent lanes at once.
//!
//! Bitslicing therefore provides two important properties:
//!
//! 1. **Parallelism:** one 16-bit logical operation evaluates 16 corresponding Boolean
//!    gates simultaneously, ie the whole state's worth of `SUBBYTES()`.
//! 2. **Constant-pattern computation:** the S-box is evaluated as a fixed Boolean circuit
//!    rather than through secret-dependent table indexing.
//!
//! The cost of those properties is real, and worth stating plainly: 113 gates plus two
//! transpositions is slower than 16 table lookups on a machine with a warm cache. What it
//! buys is that the memory access pattern no longer depends on the key.
//!
//! # Relationship between the functions in this file
//!
//! [`sub_bytes_block`] and [`inv_sub_bytes_block`]
//!     The entry points the rest of the crate uses. They take an ordinary
//!     `[u8; AES_BLOCK_LEN]` AES state, transpose it into bit planes, run the circuit, and
//!     transpose back, so the bitsliced representation never escapes this module. These are
//!     complete, correct implementations of FIPS 197 `SUBBYTES()` and `INVSUBBYTES()`.
//!
//! [`bitslice`] and [`unbitslice`]
//!     The transposition between the two representations, and each other's inverse.
//!
//! [`sub_bytes`]
//!     Evaluates the forward Boyar-Peralta-Calik AES S-box Boolean circuit on all 16
//!     bitsliced lanes simultaneously. Its eight input planes are read as `u7..u0` and
//!     its eight resulting planes are written back as `s7..s0`. **This is not the complete
//!     S-box on its own** -- see [`sub_bytes_nots`].
//!
//! [`sub_bytes_nots`]
//!     Applies the four bitwise complements omitted from [`sub_bytes`]. A scalar Boolean NOT
//!     changes one bit; in the bitsliced representation XOR with `0xffff` complements all 16
//!     lanes of a bit plane simultaneously. These NOT operations are kept separate from the
//!     main forward circuit so that an implementation which can fold them into other work --
//!     the key schedule, typically -- is free to do so.
//!
//! [`inv_sub_bytes`]
//!     Evaluates the inverse AES S-box circuit, again on all 16 lanes simultaneously. It is the
//!     inverse of the bare [`sub_bytes`] circuit, so it too needs [`sub_bytes_nots`] -- applied
//!     to its *input* rather than its output. [`inv_sub_bytes_block`] does that for you.
//!
//! # Important representation invariant
//!
//! The plane-level functions all take exactly eight words, `[u16; 8]`.
//!
//! That eight is NOT saying that AES has eight state words.
//!
//! It is saying that a bitsliced BYTE has exactly eight bit planes:
//!
//! ```text
//!     plane 0 -> AES byte bit 0   (SLP U7 / S7)
//!     plane 1 -> AES byte bit 1   (SLP U6 / S6)
//!     ...
//!     plane 7 -> AES byte bit 7   (SLP U0 / S0)
//! ```
//!
//! Each plane contains 16 lanes because one AES block contains 16 bytes. Because the plane
//! count is part of the array type, a caller cannot get it wrong: a mis-sized array is a
//! compile error rather than a runtime check.

use crate::state::AES_BLOCK_LEN;

/// The number of bit planes in the bitsliced representation: one per bit of a byte.
///
/// This is a property of the byte, not of AES, and it is the same whatever word width the
/// planes use (see the module docs on widening).
const BIT_PLANES: usize = 8;

// -------------------------------------------------------------------------------------------------
// Block-level entry points
//
// These are the only functions the rest of the crate calls. They keep the bitsliced
// representation from escaping this module: a caller hands over an ordinary AES state and gets
// back an ordinary AES state.
// -------------------------------------------------------------------------------------------------

/// SUBBYTES(): applies the AES S-box to every byte of one AES block (FIPS 197 Section 5.1.1).
///
/// Transposes the block into bit planes, evaluates the S-box circuit on all 16 lanes at once,
/// and transposes the result back.
///
/// This is the complete transformation of FIPS 197 Table 4: unlike the bare [`sub_bytes`]
/// circuit, it applies the four complements in [`sub_bytes_nots`] as well.
#[inline]
pub(crate) fn sub_bytes_block(block: &mut [u8; AES_BLOCK_LEN]) {
    let mut planes = bitslice(block);

    sub_bytes(&mut planes);
    // The circuit leaves four outputs inverted; see `sub_bytes_nots` for why this comes after.
    sub_bytes_nots(&mut planes);

    unbitslice(&planes, block);
}

/// INVSUBBYTES(): applies the inverse AES S-box to every byte of one AES block
/// (FIPS 197 Section 5.3.2).
///
/// The exact inverse of [`sub_bytes_block`].
///
/// Note the order: the complements come **first** here. [`inv_sub_bytes`] inverts the bare
/// [`sub_bytes`] circuit, so undoing `sub_bytes_block` means undoing its last step first.
/// [`sub_bytes_nots`] is its own inverse (XOR with all-ones twice is the identity), so the same
/// function serves on both sides:
///
/// ```text
/// sub_bytes_block     =  nots . circuit
/// inv_sub_bytes_block =  (nots . circuit)^-1  =  circuit^-1 . nots^-1  =  inv_circuit . nots
/// ```
#[inline]
pub(crate) fn inv_sub_bytes_block(block: &mut [u8; AES_BLOCK_LEN]) {
    let mut planes = bitslice(block);

    sub_bytes_nots(&mut planes);
    inv_sub_bytes(&mut planes);

    unbitslice(&planes, block);
}

// -------------------------------------------------------------------------------------------------
// Transposition between the byte-oriented and bitsliced representations
// -------------------------------------------------------------------------------------------------

/// Transposes one AES block into the eight bit planes the S-box circuit operates on.
///
/// Plane `p` holds bit `p` of every byte, and lane `i` of each plane is byte `i` of the block:
///
/// ```text
/// planes[p] bit i  =  block[i] bit p
/// ```
///
/// # 🚨 The SLP numbers its bits the opposite way round to FIPS 197 🚨
///
/// This is the one genuinely counter-intuitive thing in this module, so it is worth being
/// explicit. FIPS 197 Section 3.2 writes a byte as `{b7 b6 b5 b4 b3 b2 b1 b0}`, where `b7` is
/// the **most** significant bit. `SLP_AES_113` numbers its wires the other way round: `U0` and
/// `S0` are the most significant bit, and `U7`/`S7` are the least significant.
///
/// [`sub_bytes`] loads `u7` from `planes[0]`, so `planes[0]` carries the SLP's `U7`, which is
/// FIPS 197's `b0` -- hence plane `p` holding bit `p` rather than bit `7 - p`.
///
/// The circuit pins this down on its own: for an all-zero input the S-box must return `{63}`
/// (Section 5.1.1, the affine constant), and the circuit's fixed output for all-zero input is
/// `s7 s6 s5 s4 s3 s2 s1 s0 = 1 1 0 0 0 1 1 0`. Reading that with `sN` as bit `N` gives `{c6}`;
/// reading it with `sN` as bit `7 - N` gives `{63}`. Only the latter is the AES S-box, and
/// `sbox_circuit_matches_documented_examples` in this module's tests keeps it that way.
///
/// Both loop bounds are constants and the only indexing is by loop counter, so neither the
/// running time nor the memory access pattern depends on the (secret) block contents.
fn bitslice(block: &[u8; AES_BLOCK_LEN]) -> [u16; BIT_PLANES] {
    let mut planes = [0u16; BIT_PLANES];

    for (lane, &byte) in block.iter().enumerate() {
        for (p, plane) in planes.iter_mut().enumerate() {
            let bit = (byte >> p) & 1;
            *plane |= u16::from(bit) << lane;
        }
    }

    planes
}

/// Transposes eight bit planes back into one AES block; the exact inverse of [`bitslice`].
fn unbitslice(planes: &[u16; BIT_PLANES], block: &mut [u8; AES_BLOCK_LEN]) {
    for (lane, byte) in block.iter_mut().enumerate() {
        let mut value = 0u8;
        for (p, &plane) in planes.iter().enumerate() {
            let bit = ((plane >> lane) & 1) as u8;
            value |= bit << p;
        }
        *byte = value;
    }
}

// -------------------------------------------------------------------------------------------------
// Forward AES S-box
// -------------------------------------------------------------------------------------------------

/// Applies the forward AES S-box to all 16 byte lanes of one AES block simultaneously.
///
/// This is the bitsliced implementation of the AES S-box based on the
/// Boyar-Peralta-Calik / `SLP_AES_113` Boolean circuit.
///
/// `planes` is NOT eight ordinary AES words. It is eight 16-bit *bit planes*, in the SLP's bit
/// order (`U7` first, which is FIPS 197's `b0` -- see [`bitslice`]):
///
/// ```text
/// planes[0] = u7 = bit 0 of each of the 16 byte lanes
/// planes[1] = u6 = bit 1 of each of the 16 byte lanes
/// ...
/// planes[7] = u0 = bit 7 of each of the 16 byte lanes
/// ```
///
/// Thus every XOR or AND below corresponds to one Boolean gate from the S-box circuit,
/// evaluated across all 16 lanes in parallel.
///
/// See:
/// <http://www.cs.yale.edu/homes/peralta/CircuitStuff/SLP_AES_113.txt>
///
/// # 🚨 This is not the whole S-box 🚨
///
/// Four bitwise complements belonging to this formulation of the forward S-box are
/// separated out into [`sub_bytes_nots`], which must be applied to the *output* of this
/// function to obtain the S-box of FIPS 197 Table 4. Callers who do not have a reason to
/// keep the two apart should use [`sub_bytes_block`], which cannot be misused this way.
pub(crate) fn sub_bytes(planes: &mut [u16; BIT_PLANES]) {
    // The SLP operates on an 8-bit input, so in bitsliced form there are exactly eight bit
    // planes. Each plane holds one particular input bit for all 16 bytes of the state, so
    // this routine performs 16 simultaneous S-box evaluations -- one whole SUBBYTES().
    //
    // The plane count is part of the parameter type, so there is nothing to check at runtime.

    // This circuit was scheduled using:
    // https://github.com/Ko-/aes-armcortexm/tree/public/scheduler
    //
    // The circuit itself is a dependency graph of Boolean gates. A scheduler can reorder
    // independent gates without changing the Boolean function, with the goal of improving
    // register use / instruction scheduling on a target architecture.
    //
    // The historical inline "-> stack" / "<- stack" comments below therefore describe
    // suggested spills and reloads for ARM Cortex-M3/M4 implementations. They do NOT change
    // the S-box mathematics and are retained as annotations of the scheduled circuit.

    // ---------------------------------------------------------------------------------------------
    // Load the eight INPUT BIT PLANES.
    //
    // This is where the mapping from the eight `u16` plane entries to the SLP inputs occurs.
    //
    // In the original scalar SLP:
    //
    //     U7 = one bit
    //     U6 = one bit
    //     ...
    //     U0 = one bit
    //
    // Here each `uN` contains that same bit position for SIXTEEN independent bytes.
    //
    // For lane i:
    //
    //     (u7[i], u6[i], ..., u0[i])
    //
    // is one complete 8-bit input to one AES S-box, namely state byte i.
    // ---------------------------------------------------------------------------------------------
    let u7 = planes[0];
    let u6 = planes[1];
    let u5 = planes[2];
    let u4 = planes[3];
    let u3 = planes[4];
    let u2 = planes[5];
    let u1 = planes[6];
    let u0 = planes[7];

    // ---------------------------------------------------------------------------------------------
    // Top linear transformation.
    //
    // These `y*` and early `t*` values are intermediate wires from the optimized S-box circuit.
    // Most operations in this section are XORs, and are therefore linear over GF(2).
    //
    // Remember that, for example:
    //
    //     let y14 = u3 ^ u5;
    //
    // does NOT perform just one Boolean XOR. It performs 16 independent copies:
    //
    //     y14[i] = u3[i] XOR u5[i],  i = 0..15.
    // ---------------------------------------------------------------------------------------------

    let y14 = u3 ^ u5;
    let y13 = u0 ^ u6;
    let y12 = y13 ^ y14;
    let t1 = u4 ^ y12;
    let y15 = t1 ^ u5;

    // AND is the source of non-linearity in this Boolean circuit. This one machine-word
    // AND represents 16 parallel Boolean AND gates, one in each lane.
    let t2 = y12 & y15;

    let y6 = y15 ^ u7;
    let y20 = t1 ^ u1;

    // Scheduler annotation: this intermediate was suggested to be spilled to the stack.
    // It has no cryptographic significance.
    // y12 -> stack

    let y9 = u0 ^ u3;

    // y20 -> stack

    let y11 = y20 ^ y9;

    // y9 -> stack

    let t12 = y9 & y11;

    // y6 -> stack

    let y7 = u7 ^ y11;
    let y8 = u0 ^ u5;
    let t0 = u1 ^ u2;
    let y10 = y15 ^ t0;

    // y15 -> stack

    let y17 = y10 ^ y11;

    // y14 -> stack

    let t13 = y14 & y17;
    let t14 = t13 ^ t12;

    // y17 -> stack

    let y19 = y10 ^ y8;

    // y10 -> stack

    let t15 = y8 & y10;
    let t16 = t15 ^ t12;
    let y16 = t0 ^ y11;

    // y11 -> stack

    let y21 = y13 ^ y16;

    // y13 -> stack

    let t7 = y13 & y16;

    // y16 -> stack

    let y18 = u0 ^ y16;
    let y1 = t0 ^ u7;
    let y4 = y1 ^ u3;

    // u7 -> stack

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

    // y6 <- stack

    let t3 = y3 & y6;
    let t4 = t3 ^ t2;

    // y20 <- stack

    let t17 = t4 ^ y20;
    let t21 = t17 ^ t14;

    // ---------------------------------------------------------------------------------------------
    // Non-linear core.
    //
    // This middle portion contains the bulk of the AND/XOR network that gives the AES S-box its
    // non-linearity. These are optimized Boolean expressions for the same substitution FIPS 197
    // defines mathematically using inversion in GF(2^8) followed by an affine transformation.
    //
    // This implementation is NOT changing the AES S-box algorithm. It is simply an optimized
    // Boolean-circuit realization of that same function.
    // ---------------------------------------------------------------------------------------------

    let t26 = t21 & t23;
    let t27 = t24 ^ t26;
    let t31 = t22 ^ t26;
    let t25 = t21 ^ t22;

    // y4 -> stack

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

    // y16 <- stack

    let z3 = t43 & y16;
    let tc12 = z3 ^ z5;

    // tc12 -> stack
    // y13 <- stack

    let z12 = t43 & y13;
    let z13 = t40 & y5;
    let z4 = t40 & y1;
    let tc6 = z3 ^ z4;
    let t34 = t23 ^ t33;
    let t37 = t36 ^ t34;
    let t41 = t40 ^ t37;

    // y10 <- stack

    let z8 = t41 & y10;
    let z17 = t41 & y8;
    let t44 = t33 ^ t37;

    // y15 <- stack

    let z0 = t44 & y15;

    // z17 -> stack
    // y12 <- stack

    let z9 = t44 & y12;
    let z10 = t37 & y3;
    let z1 = t37 & y6;
    let tc5 = z1 ^ z0;
    let tc11 = tc6 ^ tc5;

    // y4 <- stack

    let z11 = t33 & y4;
    let t42 = t29 ^ t33;
    let t45 = t42 ^ t41;

    // y17 <- stack

    let z7 = t45 & y17;
    let tc8 = z7 ^ tc6;

    // y14 <- stack

    let z16 = t45 & y14;

    // y11 <- stack

    let z6 = t42 & y11;
    let tc16 = z6 ^ tc8;

    // z14 -> stack
    // y9 <- stack

    let z15 = t42 & y9;

    // ---------------------------------------------------------------------------------------------
    // Bottom linear transformation / output reconstruction.
    //
    // The non-linear core has now produced the information needed for the eight S-box output
    // bits. The remaining XOR network combines those intermediate signals into `s0..s7`.
    //
    // Just like the input `u*` variables, every `s*` variable is a complete 16-lane bit plane:
    //
    //     sN[i] = output bit N of SBOX(input byte in lane i)
    //
    // for all 16 lanes simultaneously.
    // ---------------------------------------------------------------------------------------------

    let tc20 = z15 ^ tc16;
    let tc1 = z15 ^ z16;
    let tc2 = z10 ^ tc1;
    let tc21 = tc2 ^ z11;
    let tc3 = z9 ^ tc2;

    let s0 = tc3 ^ tc16;
    let s3 = tc3 ^ tc11;
    let s1 = s3 ^ tc16;

    let tc13 = z13 ^ tc1;

    // u7 <- stack

    let z2 = t33 & u7;
    let tc4 = z0 ^ z2;
    let tc7 = z12 ^ tc4;
    let tc9 = z8 ^ tc7;
    let tc10 = tc8 ^ tc9;

    // z14 <- stack

    let tc17 = z14 ^ tc10;
    let s5 = tc21 ^ tc17;
    let tc26 = tc17 ^ tc20;

    // z17 <- stack

    let s2 = tc26 ^ z17;

    // tc12 <- stack

    let tc14 = tc4 ^ tc12;
    let tc18 = tc13 ^ tc14;
    let s6 = tc10 ^ tc18;
    let s7 = z12 ^ tc18;
    let s4 = tc14 ^ s3;

    // ---------------------------------------------------------------------------------------------
    // Store the eight OUTPUT BIT PLANES.
    //
    // This is the mirror image of the `u7..u0` load at the beginning of the function.
    //
    // For each lane i, the vertical tuple:
    //
    //     (s7[i], s6[i], s5[i], s4[i], s3[i], s2[i], s1[i], s0[i])
    //
    // is the eight-bit result of applying the AES S-box to:
    //
    //     (u7[i], u6[i], u5[i], u4[i], u3[i], u2[i], u1[i], u0[i]).
    //
    // Thus all 16 byte substitutions have now occurred in parallel -- modulo the four
    // complements in `sub_bytes_nots()`, which the caller still owes.
    //
    // The data remains bitsliced after this function returns; [`unbitslice`] transposes the bit
    // planes back into the ordinary byte-oriented AES state representation.
    // ---------------------------------------------------------------------------------------------

    planes[0] = s7;
    planes[1] = s6;
    planes[2] = s5;
    planes[3] = s4;
    planes[4] = s3;
    planes[5] = s2;
    planes[6] = s1;
    planes[7] = s0;
}

// -------------------------------------------------------------------------------------------------
// Forward S-box complement terms
// -------------------------------------------------------------------------------------------------

/// Applies the four bitwise NOT operations omitted from [`sub_bytes`].
///
/// In an ordinary scalar Boolean circuit, complementing one Boolean value means:
///
/// ```text
/// bit = bit XOR 1
/// ```
///
/// Here each value is a 16-lane bit plane, so we need to invert all 16 Boolean values
/// simultaneously. XOR with:
///
/// ```text
/// 0xFFFF
/// ```
///
/// means:
///
/// ```text
/// 1111111111111111
/// ```
///
/// and therefore flips every lane:
///
/// ```text
/// planes[N][i] = planes[N][i] XOR 1
///
/// for i = 0..15.
/// ```
///
/// # Why these four planes, and why afterwards
///
/// `SLP_AES_113` contains exactly four XNOR gates (written `#` in the straight-line program),
/// and they are the ones that produce four of the eight outputs:
///
/// ```text
/// S7 = z12  # tc18        S6 = tc10 # tc18
/// S1 = S3   # tc16        S2 = tc26 # z17
/// ```
///
/// [`sub_bytes`] implements all four as plain XOR, so those four outputs emerge inverted. The
/// store map at the end of that function puts `s7` in plane 0, `s6` in plane 1, `s2` in plane 5
/// and `s1` in plane 6 -- which is exactly the set of planes complemented below.
///
/// This is therefore an *output* correction, and must be applied after [`sub_bytes`], not
/// before. Applying it first would complement the inputs and compute the wrong function.
///
/// Keeping it separate lets an implementation fold these complements into other work, such as
/// pre-complementing the round keys in the key schedule, rather than spending four instructions
/// per round on them.
#[inline]
pub(crate) fn sub_bytes_nots(planes: &mut [u16; BIT_PLANES]) {
    // Again: eight entries because there are eight bit positions in each byte, not because AES
    // has an eight-word state.

    // Each XOR below performs 16 Boolean NOTs simultaneously on one output bit plane.
    planes[0] ^= 0xFFFF;
    planes[1] ^= 0xFFFF;
    planes[5] ^= 0xFFFF;
    planes[6] ^= 0xFFFF;
}

// -------------------------------------------------------------------------------------------------
// Inverse AES S-box
// -------------------------------------------------------------------------------------------------

/// Applies the inverse AES S-box to all 16 byte lanes of one AES block simultaneously.
///
/// This is the decryption-side counterpart to [`sub_bytes`]. FIPS 197's `INVSUBBYTES()`
/// applies the inverse S-box independently to every byte of the AES state. Here that inverse
/// substitution is again implemented as a bitsliced Boolean circuit.
///
/// Input representation:
///
/// ```text
/// planes[0] = u7 = bit 0 from each of the 16 bytes
/// planes[1] = u6 = bit 1 from each of the 16 bytes
/// ...
/// planes[7] = u0 = bit 7 from each of the 16 bytes
/// ```
///
/// Output representation is the same eight-plane arrangement.
///
/// # 🚨 This is not the whole inverse S-box 🚨
///
/// Like the forward direction, this circuit is only half the story: it inverts the bare
/// [`sub_bytes`] circuit, so the four complements of [`sub_bytes_nots`] have to be applied to
/// its **input** to undo the ones the forward direction applied to its output. Use
/// [`inv_sub_bytes_block`], which handles the ordering.
///
/// As with the forward circuit, names such as `t23`, `m17`, `p26`, etc. are intermediate wires
/// in an optimized Boolean circuit. Their names should generally remain unchanged so the
/// implementation can be compared against its source circuit/schedule.
pub(crate) fn inv_sub_bytes(planes: &mut [u16; BIT_PLANES]) {
    // Eight bit planes, each containing 16 independent Boolean lanes.

    // Scheduled using:
    // https://github.com/Ko-/aes-armcortexm/tree/public/scheduler
    //
    // The stack annotations below concern register allocation / scheduling on ARM Cortex-M3/M4.
    // They do not describe additional AES operations.

    // ---------------------------------------------------------------------------------------------
    // Load inverse-S-box input bit planes.
    //
    // For every lane i:
    //
    //     u7[i] ... u0[i]
    //
    // form one input byte to the AES inverse S-box.
    //
    // The assignments below therefore establish 16 simultaneous inverse-S-box invocations.
    // ---------------------------------------------------------------------------------------------
    let u7 = planes[0];
    let u6 = planes[1];
    let u5 = planes[2];
    let u4 = planes[3];
    let u3 = planes[4];
    let u2 = planes[5];
    let u1 = planes[6];
    let u0 = planes[7];

    // ---------------------------------------------------------------------------------------------
    // Inverse S-box Boolean network.
    //
    // As in the forward routine:
    //
    //     ^  = 16 parallel XOR gates
    //     &  = 16 parallel AND gates
    //
    // Every intermediate value therefore remains a 16-lane bit plane.
    // ---------------------------------------------------------------------------------------------

    let t23 = u0 ^ u3;
    let t8 = u1 ^ t23;
    let m2 = t23 & t8;
    let t4 = u4 ^ t8;
    let t22 = u1 ^ u3;
    let t2 = u0 ^ u1;
    let t1 = u3 ^ u4;

    // t23 -> stack

    let t9 = u7 ^ t1;

    // t8 -> stack

    let m7 = t22 & t9;

    // t9 -> stack

    let t24 = u4 ^ u7;

    // m7 -> stack

    let t10 = t2 ^ t24;

    // u4 -> stack

    let m14 = t2 & t10;
    let r5 = u6 ^ u7;

    // m2 -> stack

    let t3 = t1 ^ r5;

    // t2 -> stack

    let t13 = t2 ^ r5;
    let t19 = t22 ^ r5;

    // t3 -> stack

    let t17 = u2 ^ t19;

    // t4 -> stack

    let t25 = u2 ^ t1;
    let r13 = u1 ^ u6;

    // t25 -> stack

    let t20 = t24 ^ r13;

    // t17 -> stack

    let m9 = t20 & t17;

    // t20 -> stack

    let r17 = u2 ^ u5;

    // t22 -> stack

    let t6 = t22 ^ r17;

    // t13 -> stack

    let m1 = t13 & t6;
    let y5 = u0 ^ r17;
    let m4 = t19 & y5;
    let m5 = m4 ^ m1;
    let m17 = m5 ^ t24;
    let r18 = u5 ^ u6;
    let t27 = t1 ^ r18;
    let t15 = t10 ^ t27;

    // t6 -> stack

    let m11 = t1 & t15;
    let m15 = m14 ^ m11;
    let m21 = m17 ^ m15;

    // t1 -> stack
    // t4 <- stack

    let m12 = t4 & t27;
    let m13 = m12 ^ m11;
    let t14 = t10 ^ r18;
    let m3 = t14 ^ m1;

    // m2 <- stack

    let m16 = m3 ^ m2;
    let m20 = m16 ^ m13;

    // u4 <- stack

    let r19 = u2 ^ u4;
    let t16 = r13 ^ r19;

    // t3 <- stack

    let t26 = t3 ^ t16;
    let m6 = t3 & t16;
    let m8 = t26 ^ m6;

    // t10 -> stack
    // m7 <- stack

    let m18 = m8 ^ m7;
    let m22 = m18 ^ m13;

    // As with the forward S-box, these ANDs form part of the non-linear core.
    // Each individual `&` still computes 16 independent AND gates.
    let m25 = m22 & m20;
    let m26 = m21 ^ m25;
    let m10 = m9 ^ m6;
    let m19 = m10 ^ m15;

    // t25 <- stack

    let m23 = m19 ^ t25;
    let m28 = m23 ^ m25;
    let m24 = m22 ^ m23;
    let m30 = m26 & m24;
    let m39 = m23 ^ m30;
    let m48 = m39 & y5;
    let m57 = m39 & t19;

    // m48 -> stack

    let m36 = m24 ^ m25;
    let m31 = m20 & m23;
    let m27 = m20 ^ m21;
    let m32 = m27 & m31;
    let m29 = m28 & m27;
    let m37 = m21 ^ m29;

    // m39 -> stack

    let m42 = m37 ^ m39;
    let m52 = m42 & t15;

    // t27 -> stack
    // t1 <- stack

    let m61 = m42 & t1;
    let p0 = m52 ^ m61;
    let p16 = m57 ^ m61;

    // m57 -> stack
    // t20 <- stack

    let m60 = m37 & t20;

    // p16 -> stack
    // t17 <- stack

    let m51 = m37 & t17;
    let m33 = m27 ^ m25;
    let m38 = m32 ^ m33;
    let m43 = m37 ^ m38;
    let m49 = m43 & t16;
    let p6 = m49 ^ m60;
    let p13 = m49 ^ m51;
    let m58 = m43 & t3;

    // t9 <- stack

    let m50 = m38 & t9;

    // t22 <- stack

    let m59 = m38 & t22;

    // p6 -> stack

    let p1 = m58 ^ m59;
    let p7 = p0 ^ p1;
    let m34 = m21 & m22;
    let m35 = m24 & m34;
    let m40 = m35 ^ m36;
    let m41 = m38 ^ m40;
    let m45 = m42 ^ m41;

    // t27 <- stack

    let m53 = m45 & t27;
    let p8 = m50 ^ m53;
    let p23 = p7 ^ p8;

    // t4 <- stack

    let m62 = m45 & t4;
    let p14 = m49 ^ m62;
    let s6 = p14 ^ p23;

    // t10 <- stack

    let m54 = m41 & t10;
    let p2 = m54 ^ m62;
    let p22 = p2 ^ p7;
    let s0 = p13 ^ p22;
    let p17 = m58 ^ p2;
    let p15 = m54 ^ m59;

    // t2 <- stack

    let m63 = m41 & t2;

    // m39 <- stack

    let m44 = m39 ^ m40;

    // p17 -> stack
    // t6 <- stack

    let m46 = m44 & t6;
    let p5 = m46 ^ m51;

    // p23 -> stack

    let p18 = m63 ^ p5;
    let p24 = p5 ^ p7;

    // m48 <- stack

    let p12 = m46 ^ m48;
    let s3 = p12 ^ p22;

    // t13 <- stack

    let m55 = m44 & t13;
    let p9 = m55 ^ m63;

    // p16 <- stack

    let s7 = p9 ^ p16;

    // t8 <- stack

    let m47 = m40 & t8;
    let p3 = m47 ^ m50;
    let p19 = p2 ^ p3;
    let s5 = p19 ^ p24;
    let p11 = p0 ^ p3;
    let p26 = p9 ^ p11;

    // t23 <- stack

    let m56 = m40 & t23;
    let p4 = m48 ^ m56;

    // p6 <- stack

    let p20 = p4 ^ p6;
    let p29 = p15 ^ p20;
    let s1 = p26 ^ p29;

    // m57 <- stack

    let p10 = m57 ^ p4;
    let p27 = p10 ^ p18;

    // p23 <- stack

    let s4 = p23 ^ p27;
    let p25 = p6 ^ p10;
    let p28 = p11 ^ p25;

    // p17 <- stack

    let s2 = p17 ^ p28;

    // ---------------------------------------------------------------------------------------------
    // Store inverse-S-box output bit planes.
    //
    // For every lane i:
    //
    //     input  = (u7[i] ... u0[i])
    //     output = (s7[i] ... s0[i])
    //
    // Therefore, by the time these eight assignments complete, 16 independent inverse AES
    // S-box substitutions have been performed while the state remains in bitsliced form.
    // ---------------------------------------------------------------------------------------------

    planes[0] = s7;
    planes[1] = s6;
    planes[2] = s5;
    planes[3] = s4;
    planes[4] = s3;
    planes[5] = s2;
    planes[6] = s1;
    planes[7] = s0;
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{gf_mul, gf_pow};

    /// Re-derives one S-box entry from its mathematical definition, FIPS 197 Section 5.1.1.
    ///
    /// This is the specification that the Boolean circuit is an optimized realization of, so
    /// deriving it independently here is what proves the circuit computes the right function.
    /// Nothing is transcribed from Table 4, so there is no table for a typo to hide in.
    fn sbox_from_definition(b: u8) -> u8 {
        // Step 1, Eq (5.2): b~ = {00} if b == {00}, otherwise the multiplicative inverse of b.
        // Eq (4.11) gives that inverse as b^254.
        let b_tilde = if b == 0x00 { 0x00 } else { gf_pow(b, 254) };

        // Step 2, Eq (5.3): b'_i = b~_i XOR b~_(i+4 mod 8) XOR b~_(i+5 mod 8)
        //                          XOR b~_(i+6 mod 8) XOR b~_(i+7 mod 8) XOR c_i
        // where c is the constant byte {01100011} = {63}.
        const C: u8 = 0x63;
        let bit = |value: u8, i: u32| (value >> (i % 8)) & 1;

        let mut result = 0u8;
        for i in 0..8u32 {
            let b_prime_i = bit(b_tilde, i)
                ^ bit(b_tilde, i + 4)
                ^ bit(b_tilde, i + 5)
                ^ bit(b_tilde, i + 6)
                ^ bit(b_tilde, i + 7)
                ^ bit(C, i);
            result |= b_prime_i << i;
        }
        result
    }

    /// Runs one byte through [`sub_bytes_block`] by filling a whole block with it.
    ///
    /// Filling every lane rather than just lane 0 also checks that the circuit really does treat
    /// the lanes independently: all 16 outputs must agree.
    fn sbox(b: u8) -> u8 {
        let mut block = [b; AES_BLOCK_LEN];
        sub_bytes_block(&mut block);
        assert!(block.iter().all(|&x| x == block[0]), "lanes disagreed for {b:#04x}");
        block[0]
    }

    /// The same, for the inverse circuit.
    fn inv_sbox(b: u8) -> u8 {
        let mut block = [b; AES_BLOCK_LEN];
        inv_sub_bytes_block(&mut block);
        assert!(block.iter().all(|&x| x == block[0]), "lanes disagreed for {b:#04x}");
        block[0]
    }

    /// Every one of the 256 possible input bytes must come out of the Boolean circuit equal to
    /// the value FIPS 197 Eq (5.2) and (5.3) define.
    ///
    /// This is also the test that pins the ordering of [`sub_bytes_nots`] relative to
    /// [`sub_bytes`]: getting it backwards complements the inputs instead of the outputs, which
    /// this check would catch on the very first byte.
    #[test]
    fn sbox_circuit_matches_its_mathematical_definition() {
        for b in 0..=u8::MAX {
            assert_eq!(sbox(b), sbox_from_definition(b), "SBOX({b:#04x})");
        }
    }

    /// Two spot checks straight out of the prose of FIPS 197.
    #[test]
    fn sbox_circuit_matches_documented_examples() {
        // Section 5.1.1: "if s_rc = {53} ... so that s'_rc = {ed}".
        assert_eq!(sbox(0x53), 0xed);
        // Section 5.1.1: SBOX({00}) is the affine transform of {00}, ie the constant {63}.
        assert_eq!(sbox(0x00), 0x63);
    }

    /// The inverse circuit must invert the forward one in both directions, for every byte.
    /// Checking both directions also proves each is a bijection, ie a genuine permutation of the
    /// 256 byte values (FIPS 197 Section 5.3.2).
    #[test]
    fn inv_sbox_circuit_inverts_sbox_circuit() {
        for b in 0..=u8::MAX {
            assert_eq!(inv_sbox(sbox(b)), b, "INVSBOX(SBOX({b:#04x}))");
            assert_eq!(sbox(inv_sbox(b)), b, "SBOX(INVSBOX({b:#04x}))");
        }
    }

    /// The S-box has no fixed points (SBOX(b) != b) and no "opposite" fixed points
    /// (SBOX(b) != !b). These are design properties of Rijndael's affine constant, so they are a
    /// cheap independent sanity check on the circuit.
    #[test]
    fn sbox_circuit_has_no_fixed_points() {
        for b in 0..=u8::MAX {
            assert_ne!(sbox(b), b, "SBOX has a fixed point at {b:#04x}");
            assert_ne!(sbox(b), !b, "SBOX has an opposite fixed point at {b:#04x}");
        }
    }

    /// [`sub_bytes`] on its own is deliberately *not* the S-box: four of its outputs come out
    /// inverted. This pins that the missing piece is exactly [`sub_bytes_nots`] and nothing else,
    /// so that an implementation which folds those complements elsewhere knows what it owes.
    #[test]
    fn sub_bytes_without_nots_differs_only_by_the_four_complements() {
        for b in 0..=u8::MAX {
            let block = [b; AES_BLOCK_LEN];

            let mut raw = bitslice(&block);
            sub_bytes(&mut raw);

            let mut corrected = raw;
            sub_bytes_nots(&mut corrected);

            // Planes 0, 1, 5 and 6 are the XNOR-derived outputs s7, s6, s2 and s1.
            for p in 0..BIT_PLANES {
                let expected =
                    if matches!(p, 0 | 1 | 5 | 6) { !raw[p] } else { raw[p] };
                assert_eq!(corrected[p], expected, "plane {p} for input {b:#04x}");
            }
        }
    }

    /// [`bitslice`] and [`unbitslice`] must be exact inverses, and must place each byte in its
    /// own lane. A block of 16 distinct bytes catches any lane or bit-order transposition error.
    #[test]
    fn bitslice_round_trips() {
        let mut block = [0u8; AES_BLOCK_LEN];
        for (i, byte) in block.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(17).wrapping_add(1);
        }

        let planes = bitslice(&block);
        let mut recovered = [0u8; AES_BLOCK_LEN];
        unbitslice(&planes, &mut recovered);

        assert_eq!(recovered, block);
    }

    /// The documented plane/lane mapping must hold literally: plane `p` bit `i` is bit `p` of
    /// byte `i`. Pinning it means the surrounding code can rely on the layout, and it guards the
    /// SLP-versus-FIPS bit-numbering trap documented on [`bitslice`].
    #[test]
    fn bitslice_places_bits_where_documented() {
        let mut block = [0u8; AES_BLOCK_LEN];
        for (i, byte) in block.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(31).wrapping_add(7);
        }

        let planes = bitslice(&block);

        for (i, &byte) in block.iter().enumerate() {
            for (p, &plane) in planes.iter().enumerate() {
                let from_plane = ((plane >> i) & 1) as u8;
                let from_byte = (byte >> p) & 1;
                assert_eq!(from_plane, from_byte, "plane {p}, lane {i}");
            }
        }
    }
}
