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
//! # Why are the inputs `u64` if an AES S-box takes bits?
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
//! A bitsliced representation conceptually transposes that matrix:
//!
//! ```text
//!     u7 = [a7 b7 c7 d7]
//!     u6 = [a6 b6 c6 d6]
//!     u5 = [a5 b5 c5 d5]
//!     ...
//!     u0 = [a0 b0 c0 d0]
//! ```
//!
//! This implementation uses a `u64` for every row of that transposed representation.
//! Consequently each word has 64 independent Boolean lanes:
//!
//! ```text
//!                   64 independent byte positions
//!
//!                   lane 63 ... lane 2 lane 1 lane 0
//!
//!     state[0] = u7   b7       ...   b7     b7     b7
//!     state[1] = u6   b6       ...   b6     b6     b6
//!     state[2] = u5   b5       ...   b5     b5     b5
//!     state[3] = u4   b4       ...   b4     b4     b4
//!     state[4] = u3   b3       ...   b3     b3     b3
//!     state[5] = u2   b2       ...   b2     b2     b2
//!     state[6] = u1   b1       ...   b1     b1     b1
//!     state[7] = u0   b0       ...   b0     b0     b0
//!
//!                        |                 |
//!                        | one vertical   |
//!                        | column is one  |
//!                        | AES byte       |
//! ```
//!
//! Therefore:
//!
//! ```text
//!     8 u64 words
//!       = 8 bit planes
//!
//!     each plane
//!       = 64 independent bits
//!
//!     8 planes x 64 lanes
//!       = 64 independent 8-bit values
//!       = 64 bytes represented simultaneously
//! ```
//!
//! The apparent size of the representation is therefore:
//!
//! ```text
//!     8 * 64 = 512 storage bits
//! ```
//!
//! but this DOES NOT mean that AES suddenly has a 512-bit block.
//!
//! AES's block size is still exactly:
//!
//! ```text
//!     16 bytes = 128 bits
//! ```
//!
//! The 512 bits here are a parallel implementation representation. When the surrounding
//! AES implementation packs four complete AES states into one such bitsliced window,
//! those 64 byte lanes correspond exactly to:
//!
//! ```text
//!     4 AES blocks
//!       x 16 bytes per AES block
//!       = 64 independently substituted bytes
//! ```
//!
//! Thus this function can evaluate the S-box needed for the `SUBBYTES()` operations of
//! four AES blocks in parallel.
//!
//! Importantly, the fact that the `[u64; 8]` representation *can* hold 64 byte lanes is
//! intrinsic to this function. The interpretation of those lanes as four complete
//! 16-byte AES blocks comes from the surrounding code that packs AES states into this
//! bitsliced representation. This function itself neither knows nor cares where a lane
//! came from: it simply computes 64 independent AES S-box evaluations.
//!
//! # Why a single XOR or AND performs 64 S-box gates
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
//! `u3` and `u5` are `u64`s. Rust's `^` operates bit-by-bit across the whole word, so
//! this performs:
//!
//! ```text
//!     y14[0]  = u3[0]  XOR u5[0]
//!     y14[1]  = u3[1]  XOR u5[1]
//!     ...
//!     y14[63] = u3[63] XOR u5[63]
//! ```
//!
//! In other words, ONE machine-word XOR evaluates that Boolean gate for all 64 S-box
//! invocations simultaneously.
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
//!     for every lane i = 0..63 simultaneously.
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
//! evaluates the corresponding Boolean gate across 64 independent lanes at once.
//!
//! Bitslicing therefore provides two important properties:
//!
//! 1. **Parallelism:** one 64-bit logical operation evaluates 64 corresponding Boolean
//!    gates simultaneously.
//! 2. **Constant-pattern computation:** the S-box is evaluated as a fixed Boolean circuit
//!    rather than through secret-dependent table indexing.
//!
//! # Relationship between the functions in this file
//!
//! `sub_bytes()`
//!     Evaluates the forward Boyar-Peralta-Calik AES S-box Boolean circuit on all 64
//!     bitsliced lanes simultaneously. Its eight input planes are read as `u7..u0` and
//!     its eight resulting planes are written back as `s7..s0`.
//!
//! `sub_bytes_nots()`
//!     Applies four bitwise complements associated with the Boolean formulation of the
//!     forward S-box. A scalar Boolean NOT changes one bit; in the bitsliced
//!     representation XOR with `0xffffffffffffffff` complements all 64 lanes of a bit
//!     plane simultaneously. In this implementation these NOT operations are separated
//!     from the main forward circuit so they can be accounted for elsewhere, including
//!     by the key schedule.
//!
//! `inv_sub_bytes()`
//!     Evaluates the inverse AES S-box circuit, again on all 64 lanes simultaneously.
//!     Unlike the forward routine above, its comments state that the required complement
//!     operations are accounted for inside the inverse implementation so that it is the
//!     true inverse of the representation produced by `sub_bytes()`.
//!
//! # Important representation invariant
//!
//! All three functions expect exactly eight `u64` words:
//!
//! ```text
//!     state.len() == 8
//! ```
//!
//! That assertion is NOT asserting that AES has eight 64-bit state words.
//!
//! It is asserting that a bitsliced BYTE has exactly eight bit planes:
//!
//! ```text
//!     plane 0 -> AES byte bit 7
//!     plane 1 -> AES byte bit 6
//!     ...
//!     plane 7 -> AES byte bit 0
//! ```
//!
//! Each plane happens to contain 64 independent lanes because the implementation uses
//! 64-bit machine words.

// -------------------------------------------------------------------------------------------------
// Forward AES S-box
// -------------------------------------------------------------------------------------------------

/// Applies the forward AES S-box to 64 independent byte lanes simultaneously.
///
/// This is the bitsliced implementation of the AES S-box based on the
/// Boyar-Peralta-Calik / `SLP_AES_113` Boolean circuit.
///
/// `state` is NOT eight ordinary AES words. It is eight 64-bit *bit planes*:
///
/// ```text
/// state[0] = bit 7 of each of the 64 byte lanes
/// state[1] = bit 6 of each of the 64 byte lanes
/// ...
/// state[7] = bit 0 of each of the 64 byte lanes
/// ```
///
/// Thus every XOR or AND below corresponds to one Boolean gate from the S-box circuit,
/// evaluated across all 64 lanes in parallel.
///
/// See:
/// <http://www.cs.yale.edu/homes/peralta/CircuitStuff/SLP_AES_113.txt>
///
/// Note that four bitwise complement operations belonging to this formulation of the
/// forward S-box are separated into [`sub_bytes_nots`] and are accounted for by the
/// surrounding implementation/key schedule.
pub(crate) fn sub_bytes(state: &mut [u64]) {
    // The SLP operates on an 8-bit input. In bitsliced form we therefore require exactly
    // eight bit planes. Each plane contains 64 parallel copies of one particular input bit,
    // giving this routine capacity for 64 simultaneous S-box evaluations.
    //
    // This is 8 * 64 = 512 bits of REPRESENTATION, not a 512-bit AES state.
    debug_assert_eq!(state.len(), 8);

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
    // This is where the mapping from the eight `u64` state entries to the SLP inputs occurs.
    //
    // In the original scalar SLP:
    //
    //     U7 = one bit
    //     U6 = one bit
    //     ...
    //     U0 = one bit
    //
    // Here each `uN` contains that same bit position for SIXTY-FOUR independent bytes.
    //
    // For lane i:
    //
    //     (u7[i], u6[i], ..., u0[i])
    //
    // is one complete 8-bit input to one AES S-box.
    //
    // If the surrounding state-packing code has filled these 64 lanes from four AES blocks,
    // then lanes 0..63 collectively represent 4 * 16 = 64 AES state bytes.
    // ---------------------------------------------------------------------------------------------
    let u7 = state[0];
    let u6 = state[1];
    let u5 = state[2];
    let u4 = state[3];
    let u3 = state[4];
    let u2 = state[5];
    let u1 = state[6];
    let u0 = state[7];

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
    // does NOT perform just one Boolean XOR. It performs 64 independent copies:
    //
    //     y14[i] = u3[i] XOR u5[i],  i = 0..63.
    // ---------------------------------------------------------------------------------------------

    let y14 = u3 ^ u5;
    let y13 = u0 ^ u6;
    let y12 = y13 ^ y14;
    let t1 = u4 ^ y12;
    let y15 = t1 ^ u5;

    // AND is the source of non-linearity in this Boolean circuit. This one machine-word
    // AND represents 64 parallel Boolean AND gates, one in each lane.
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
    // Just like the input `u*` variables, every `s*` variable is a complete 64-lane bit plane:
    //
    //     sN[i] = output bit N of SBOX(input byte in lane i)
    //
    // for all 64 lanes simultaneously.
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
    // Thus all 64 byte substitutions have now occurred in parallel.
    //
    // The data remains bitsliced after this function returns; some surrounding operation must
    // eventually transpose/unpack the bit planes back into the ordinary byte-oriented AES state
    // representation when required.
    // ---------------------------------------------------------------------------------------------

    state[0] = s7;
    state[1] = s6;
    state[2] = s5;
    state[3] = s4;
    state[4] = s3;
    state[5] = s2;
    state[6] = s1;
    state[7] = s0;
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
/// Here each value is a 64-lane bit plane, so we need to invert all 64 Boolean values
/// simultaneously. XOR with:
///
/// ```text
/// 0xFFFFFFFFFFFFFFFF
/// ```
///
/// means:
///
/// ```text
/// 1111111111111111111111111111111111111111111111111111111111111111
/// ```
///
/// and therefore flips every lane:
///
/// ```text
/// state[N][i] = state[N][i] XOR 1
///
/// for i = 0..63.
/// ```
///
/// The four affected planes correspond to the four complemented/XNOR-derived outputs in the
/// Boolean formulation used by the forward S-box. The surrounding AES implementation may fold
/// these complements into other work, such as the key schedule, rather than performing them
/// directly inside [`sub_bytes`].
#[inline]
pub(crate) fn sub_bytes_nots(state: &mut [u64]) {
    // Again: eight entries because there are eight bit positions in each byte, not because AES
    // has an eight-word or 512-bit state.
    debug_assert_eq!(state.len(), 8);

    // Each XOR below performs 64 Boolean NOTs simultaneously on one output bit plane.
    state[0] ^= 0xFFFFFFFFFFFFFFFF;
    state[1] ^= 0xFFFFFFFFFFFFFFFF;
    state[5] ^= 0xFFFFFFFFFFFFFFFF;
    state[6] ^= 0xFFFFFFFFFFFFFFFF;
}

// -------------------------------------------------------------------------------------------------
// Inverse AES S-box
// -------------------------------------------------------------------------------------------------

/// Applies the inverse AES S-box to 64 independent byte lanes simultaneously.
///
/// This is the decryption-side counterpart to [`sub_bytes`]. FIPS 197's `INVSUBBYTES()`
/// applies the inverse S-box independently to every byte of the AES state. Here that inverse
/// substitution is again implemented as a bitsliced Boolean circuit.
///
/// Input representation:
///
/// ```text
/// state[0] = u7 = bit 7 from each of 64 independent bytes
/// state[1] = u6 = bit 6 from each of 64 independent bytes
/// ...
/// state[7] = u0 = bit 0 from each of 64 independent bytes
/// ```
///
/// Output representation is the same eight-plane arrangement.
///
/// Unlike the forward `sub_bytes()` routine above, the required complement terms are accounted
/// for inside this inverse circuit so that it implements the true inverse transformation of the
/// forward representation.
///
/// As with the forward circuit, names such as `t23`, `m17`, `p26`, etc. are intermediate wires
/// in an optimized Boolean circuit. Their names should generally remain unchanged so the
/// implementation can be compared against its source circuit/schedule.
pub(crate) fn inv_sub_bytes(state: &mut [u64]) {
    // Eight bit planes, each containing 64 independent Boolean lanes.
    debug_assert_eq!(state.len(), 8);

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
    // The assignments below therefore establish 64 simultaneous inverse-S-box invocations.
    // ---------------------------------------------------------------------------------------------
    let u7 = state[0];
    let u6 = state[1];
    let u5 = state[2];
    let u4 = state[3];
    let u3 = state[4];
    let u2 = state[5];
    let u1 = state[6];
    let u0 = state[7];

    // ---------------------------------------------------------------------------------------------
    // Inverse S-box Boolean network.
    //
    // As in the forward routine:
    //
    //     ^  = 64 parallel XOR gates
    //     &  = 64 parallel AND gates
    //
    // Every intermediate value therefore remains a 64-lane bit plane.
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
    // Each individual `&` still computes 64 independent AND gates.
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
    // Therefore, by the time these eight assignments complete, 64 independent inverse AES
    // S-box substitutions have been performed while the state remains in bitsliced form.
    // ---------------------------------------------------------------------------------------------

    state[0] = s7;
    state[1] = s6;
    state[2] = s5;
    state[3] = s4;
    state[4] = s3;
    state[5] = s2;
    state[6] = s1;
    state[7] = s0;
}