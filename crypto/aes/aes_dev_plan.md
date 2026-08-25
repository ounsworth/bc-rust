# Status at a glance (2026-08-25)

`cargo test -p bouncycastle-aes` -> **44 tests pass**, no warnings, `cargo fmt --check` and
`cargo doc` clean.

| | |
|---|---|
| src | 6 files, ~2735 lines |
| tests | 28 unit (in-src) + 10 `aes_tests.rs` + 6 across the three `bc_test_data*.rs` |
| conformance | FIPS 197 App. A.1/A.2/A.3 + App. B (incl. every intermediate); SP 800-38A F.1; **ACVP-AES-ECB: all 2138 AFT + all 6 MCT** |
| fallibility | 3 production `unwrap()` (2 in `key_schedule.rs`, 1 in `sbox.rs`), 3 `Err()` (all in `AES::new`) |
| outstanding | CBC + GCM, crate docs, benches, 34 `// TODO`s |

Note `quality_stats.sh` reports 14 "unwraps in core code" because it counts everything under `src/`
including the in-src test modules; the production figure is 3.

# Phase 1: Pure rust impl

- [ ] Start with `rijndael.rs`, maybe `key_schedule.rs`, then add `aes.rs` -- ideally there can be one `struct AES<..>`
  superfished to encapsulate all the differences between 128, 192, 256.
    - I think `rijndael.rs` includes all the functions defined in section 5, parametrized (superfished) to take the
      constants Nr, Nk, etc.
    - Let's do `key_schedule.rs` as a separate because I think we'll want a bunch of different versions of that --
      streaming, pre-computed, etc, so we'll want a `struct KeySchedule<..>` that we can `pub use` from `lib.rs`. To
      conform to FIPS 197, we'll want a one-shot `fn KeyExpansion(key) -> KeySchedule`, but we'll also want a streaming
      version. By the time we're done optimizing, probably the one-shot will only be used in the pre-expanded mode and
      the default mode uses the streaming version to reduce memory footprint. It might make sense for
      `struct KeySchedule` to have fn's `.next_key() -> [u8; KEY_LEN]`, and also somewhere a
      `.pre_expand() -> PreExpandedKeySchedule`.
    - STATUS: `struct AES<KEY_LEN, Nr, Nroundkeys>` + the `AES128`/`AES192`/`AES256` aliases landed, sealed to the three
      FIPS Table 3 parameter sets by `where Self: Algorithm` plus a `VALID_PARAMS` const assert. `rijndael.rs` is
      parametrized as described.
    - OUTSTANDING: `KeySchedule` is a newtype over `[RoundKey; Nroundkeys]`, not a `struct` with behaviour -- Since KeySchedule is NOT publically exposed, it's 
      only callable internally within the AES crate.
      This is because `KeySchedule` is not an officially
      listed function in 2.2, hence no need to expose it.
      If intend to publicly expose it, streaming `.next_key()`, no `.pre_expand()`, and it is not `pub use`d. `KeyScheduleEIC` is its `dw` counterpart
      (see EqInvCipher below); the two are separate types so they cannot be swapped by mistake.
- ✅ How to model the state `s`? It would be sweet to impl something so that you can do `s[r,c] = x` and a
  `from<[u8;16]>` and `into<[u8;16]>` so that our source code will look extremely like the sample code and Table 1.
    - Resolved, but not with an indexing type: the state is a flat `[u8; 16]` laid out in Eq (3.6) order, so
      `state[r + 4c]` *is* `s[r, c]`, a column is a contiguous 4 bytes, and copying a block in or out is a plain
      16-byte copy. That made the `s[r,c]` sugar and the From/Into unnecessary. See the `state.rs` module docs.
- [ ] impl all the functions listed in 2.2 with the API exactly as listed, function bodies of a non-trivial length
  should be inline commented with the corresponding line (s) from the FIPS sample algs. (it doesn't need to stay this
  way, but provides a base for later optimization)
    - STATUS: every function in s. 2.2 exists and is commented line-by-line against the spec, **except** the two
      deliberate deviations below. Present: `Cipher` (Alg 1), `InvCipher` (Alg 3), `EqInvCipher` (Alg 4),
      `KeyExpansion` (Alg 2), `KeyExpansionEIC` (Alg 5), `AddRoundKey`, `SubBytes`/`InvSubBytes`,
      `ShiftRows`/`InvShiftRows`, `MixColumns`/`InvMixColumns`, `SubWord`, `RotWord`, `xTimes`.
    - DEVIATION 1: there is no scalar `SBox(b: u8) -> u8` / `InvSBox()`. The bitsliced circuit substitutes all 16 bytes
      of the state simultaneously, so a byte-at-a-time S-box would be a different (and table-shaped) implementation.
      What exists instead is `sub_bytes`/`inv_sub_bytes` over a whole state, and `sub_word` over one word -- and
      `sub_word` already pays for this by zero-padding a word out to a full state. See the Phase 3 optimization item.
    - DEVIATION 2: `AES-128()`/`AES-192()`/`AES-256()` are *types*, not free functions: `AES128::encrypt_block(&self)`
      for the reusable engine and `AES128::encrypt_single_block(key, block)` for the one-shot. Eq (5.1) as a free
      function would have to re-expand the key on every call.
    - DECIDE: is the above acceptable as "the API exactly as listed", or do we want thin `SBox()` and `AES_128()`
      wrappers for spec-correspondence? Leaving unticked until that call is made.
- [ ] There is good stuff in the nursery -- maybe it makes sense to mock out the function signatures we want, then go
  hunting for function bodies in the nursery?
    - STATUS: the predecessor branch `feature/officialfrancismendoza/64-AES-block-cipher-engine` was mined for the
      engine shape (the `where Self: Algorithm` sealing, `VALID_PARAMS`, the key checks in `new()`) and the SP 800-38A
      F.1 known-answer vectors. Its lookup-table `tables.rs` S-box was deliberately left behind in favour of the
      bitsliced one. 
- ✅ Let's implement `EqInvCipher` after implementing the straightforward one so that we understand the perf-size
  tradeoffs that it represents, then we can decide whether to keep both or only keep one.
    - STATUS: Implemented. Alg 4 in `rijnael.rs`, Alg 5 in `key_schedule.rs`, with `dw` typed as `KeyScheduleEIC` so
      that handing the wrong schedule to the wrong algorithm is a compile error rather than silent garbage.
    - OUTSTANDING: not wired into the engine, so both carry `#[allow(dead_code)]` and are reached only from tests. The
      keep-both-or-one decision needs benches -- moved to Phase 3.
- ✅ Consider side-channel implications, particularly of the sbox -- is it ok for this to be lookup-table based, or do
  we need to do something extra clever?
    - Not lookup-table based: `sbox.rs` evaluates the Boyar-Peralta-Calik `SLP_AES_113` Boolean circuit over a
      bitsliced state, so there is no secret-indexed memory access and no branching. The GF(2^8) multipliers in
      `state.rs` are branch-free for the same reason. Still to consider under this heading when the modes land:
      GHASH's GF(2^128) multiply has exactly the same table-lookup temptation.
- [ ] Basic Modes: CBC, GCM. (s. 6.5)
    - STATUS: not started. `AES_CBC` and `AES_GCM` are empty stubs in `aes.rs` with their trait impls commented out.
    - Two constraints that fell out of reading the ACVP vectors, both worth settling *before* writing the modes:
    - CBC: the vectors are unpadded whole blocks, so whatever padding scheme CBC adopts has to be bypassable or the
      conformance vectors cannot be checked at all. Also needs a caller-supplied-IV entry point, since
      `SymmetricCipher::encrypt` generates its own IV and so cannot reproduce a fixed vector.
    - GCM: needs an explicit-nonce encrypt entry point for the same reason (`AEADCipher::aead_encrypt` generates its
      own nonce -- the same gap the mlkem harness works around with `encaps_internal`). The ACVP set is all 96-bit
      IVs, the one length that skips GHASH in the J0 derivation; other lengths need the other branch. Tags come both
      truncated (96-bit) and full (128-bit).
    - Both modes will need a runtime dependency on `bouncycastle-rng` (`HashDRBG_SHA512::new_from_os()`, as ASCON and
      mlkem do) because the trait one-shots generate the IV/nonce themselves. That would be this crate's first runtime
      dep beyond `core`/`utils`, so flag it in review.
    - DECIDE: modes here in `crypto/aes`, or their own crates? There is a recorded decision favouring separate crates
      (NIST CSOR assigns AES OIDs per mode, never to the bare cipher), but the stubs currently live in `aes.rs`. Either
      way the raw engine must NOT implement `SymmetricCipher`/`BlockCipher` -- the only mode it can offer is ECB, and
      `core-test-framework`'s `TestFrameworkBlockCipher` asserts `assert_ne!(iv1, iv2)` across two `do_encrypt_init()`
      calls, which a zero-length-IV engine can never satisfy.
- [ ] Once working, go wrap everything in `Secret<>`.
    - STATUS: the round state in `cipher()`/`inv_cipher()`/`eq_inv_cipher()`, every key schedule word, and the
      per-round key buffer in `key_expansion_eic()` are wrapped. The modes' chaining values and GHASH state will need
      it too.
- ✅ Build basic unit tests as we go.
    - 28 in-src unit tests: FIPS 197 Appendix A.1/A.2/A.3 (key schedule), Appendix B end to end **plus every
      intermediate state of all ten rounds** (`appdx_b_round_trace`, printable with `--nocapture`), `add_round_key` on
      its own, the four transformations against NIST intermediate values, the S-box exhaustively over all 256 bytes,
      the GF(2^8) multipliers over all 256 inputs, and EqInvCipher agreeing with InvCipher for all three key sizes.
      Locking down *all* behaviours is Phase 2.

# Phase 2: Tests

- [ ] Fill out unit tests to lock down all behaviours. `cargo mutants` is very helpful at telling you when you're done.
    - STATUS: 28 unit + 10 integration. `cargo mutants` has not been run on this crate yet -- that is the gate for
      calling this done.
    - Test placement was audited against QUALITY_AND_STYLE.md and settled as: anything observable through the public
      `AES` engine is an integration test in `tests/`; anything that needs a `pub(crate)` item (the transformations, the
      GF multipliers, Appendix A's exact schedule words, Appendix B's intermediate states) stays an in-src
      `#[cfg(test)] mod`, per QUALITY_AND_STYLE.md's rule for private functions. No production visibility was widened
      for test access. Note QUALITY_AND_STYLE.md also mandates `src/tests`, which no crate in the workspace uses.
- [ ] bc-test-data
    - Harnesses live in `tests/bc_test_data*.rs`, modelled on `crypto/mldsa/tests`. They look for the repo at
      `../../../bc-test-data` (from the crate dir) or `../bc-test-data` (from the workspace root) and pass with a
      warning if it is not cloned -- all three code paths verified. The vectors are in
      `bc-test-data/crypto/aes_tdes_vectors/{AES,CCM,CMAC,GCM}`, in ACVP JSON:
      `<algorithm>.<sessionId>.{req,rsp,res}.json` for prompts / answers / NIST's verdict. Files are located by prefix
      because the session id changes whenever the vectors are regenerated. Each harness also asserts its session's
      `.res.json` disposition is `passed`, so vectors from a failed session cannot quietly become the reference.
    - ✅ `tests/bc_test_data.rs` -- ACVP-AES-ECB, **complete**. All 2138 AFT vectors (2408 blocks, both directions,
      all three key sizes) and all 6 MCT vectors (600,000 chained block operations). An ACVP-AES-ECB AFT vector is just
      a known-answer test for the raw permutation, which is why this set is runnable against the engine with no mode.
    - [ ] `tests/bc_test_data_cbc.rs` -- ACVP-AES-CBC. Blocked on AES_CBC. The harness already locates, parses and
      validates all 2150 AFT vectors against their group parameters; finish it by filling in `CbcTestCase::run()` and
      flipping `AES_CBC_IS_IMPLEMENTED`. Its 6 MCT cases need the CBC chaining variant of the algorithm now working for
      ECB.
    - [ ] `tests/bc_test_data_gcm.rs` -- ACVP-AES-GCM. Blocked on AES_GCM. Same state: 270 vectors located, parsed and
      validated. 29 of them are forged tags that must be **rejected** with `AEADTagCheckFailed`, so a GCM that ignored
      its tag would still pass the other 241 -- those 29 are the ones that matter.
    - [ ] ACVP-AES-GMAC -- same directory, same algorithm with an empty payload. Wants a sibling harness once GCM works.
    - [ ] The rest of `aes_tdes_vectors/AES` once the corresponding modes exist: CTR, CFB8, CFB128, OFB, KW, KWP,
      FF1, FF3-1, and the CBC ciphertext-stealing variants CBC-CS1/CS2/CS3. Plus `CCM/` and `CMAC/`.
- ✅ wycheproof -- cloned at `../wycheproof` (sibling of this repo, same as bc-test-data). Not started for AES. Model
  on `crypto/mlkem/tests/wycheproof.rs`.
- [ ] Create perf and mem benches
    - STATUS: not started. There is no `benches/` directory and the `[[bench]]` section in `Cargo.toml` is still
      commented out. QUALITY_AND_STYLE.md requires criterion benches per crate, and separate benches for variants with
      different performance characteristics (so: pre-expanded vs streaming key schedule, once those exist).
    - Several Phase 3 items are explicitly blocked on having these numbers.
    - A `mem_usage_benches/` harness is probably not warranted: the engine's stack use is a small constant.

# Phase 3: De-duplication & Optimization

- [ ] De-duplicate code. Goal: reduce code review and test footprint by merging code where possible.
    - The key expansion recurrence is written out twice: `key_expansion` (Alg 2) and `key_expansion_eic` (Alg 5) each
      spell it out, because Alg 5 was transcribed line-by-line against the FIPS rather than delegating. Alg 5 also
      holds two full schedules at once (~480 bytes for AES-256 vs ~240); collapsing it would halve that.
    - `rot_word` has a second implementation, `rot_word_coreys_way` (`word.rotate_left(8)`), kept `#[cfg(test)]` with
      an equivalence test. One instruction instead of a byte shuffle -- swap it in here.
    - `state.rs` vs `rijnael.rs`: `state.rs`'s own TODO suggests merging the used functions into `rijnael.rs` and
      deleting the file. Decide either way and record it.
- [ ] Squeeze down perf & memory footprint.
    - `cipher()`/`inv_cipher()` copy the block into a `Secret` state rather than working in place; saves 16 bytes to
      change, may cost speed. Needs a before/after bench.
    - `sub_word()` zero-pads one word out to a full 16-byte state to reuse the bitsliced circuit. A `bitslice_word()`
      would avoid shuffling 12 zero bytes -- the sbox.rs TODO calls the gain "probably negligible", so measure first.
    - The 113-`let` S-box circuit: does it really cost ~226 bytes of stack, or does LLVM coalesce it?
- [ ] The parallelized SBox, can we increase it from u16 lanes to u64 lanes for more perf?
- [ ] Decide whether to keep `EqInvCipher` at all. It is implemented and tested but not wired in; keeping it means the
  engine stores or derives a second key schedule per instance, which is exactly the perf/size tradeoff to measure. If
  it stays, wire it in and drop the `#[allow(dead_code)]`s.
- [ ] Read s. 6.4 and its references carefully for optimization hints.

# Phase 4: Bells & Whistles

- [ ] Add additional feature APIs -- ex.: exposing internal params, `_rng()` versions of fn's that consume entropy,
  exposing APIs for places where you can pre-compute things like key schedules (ie fast vs small mode), etc.
- [ ] Note from the nursery implementation: "One other thing to ponder, mentioning it now in case I forget later, with
  the one shot stuff, with symmetric ciphers like AES computing the key schedule is often regarded as quite expensive
  when everything is getting done in software, it would be nice to have some way to pass a precalculated key schedule in
  as it's quite common for people to want to the ECB mode once and then do GCM/CTR/CBC on top of the engine varying the
  IV/nonce accordingly. We have a mechanism for doing this in BC java (not that I would suggest the mechanism is
  appropriate for Rust) and it was introduced by popular request."
- [ ] Compare to other crates to make sure we have all bc-rust features implemented (things like Suspendable, Algorithm,
  cli, factory, etc).
    - STATUS: `Algorithm` is implemented (for the three aliases only, which is what seals the parameter sets). Missing:
      no `cli/` subcommand, no factory registration, not re-exported from the umbrella `bouncycastle` crate, no
      `AlgorithmOID`, no `Suspendable`.
    - Per the recorded scope decision these belong to the *mode* crates, not the raw engine: NIST CSOR assigns AES OIDs
      per mode, the cipher traits are about encrypting data rather than permuting a block, and `Suspendable` has
      nothing to serialize here but the key schedule. Confirm that reading before adding any of them.
- [ ] Other modes:
    - Key Wrap (KW and KWP from SP 800-38F)
    - CMAC (SP 800-38B / RFC4493)
    - GMAC (SP 800-38D / RFC9044)
    - CCM? This is basically a standardized version of AES_CBC+MAC, but is strictly worse than AES_GCM, what I don't
      know is whether any protocols still use it, or if everything has moved to GCM.
    - CTR, CFB8, CFB128, OFB and the CBC-CS1/CS2/CS3 ciphertext-stealing variants all have bc-test-data vectors waiting
      if any of them turn out to be worth implementing.
- [ ] feature `hwaccel = ["avx", "aesni"]` -- add these as cargo features, maybe utilizing a new crate
  `bouncycastle-hwaccel` which holds all the unsafe and arch-specific assembly. (some of this might already exist in the
  nursery impl).
    - This is also what makes GCM fast: `pclmulqdq` / `vmull` for the GF(2^128) multiply.
- [ ] `#[no_std]` and cargo `alloc` feature. Then start adding guards that `Box<>` stuff onto the heap when the `alloc`
  feature is enabled.
    - `#![no_std]` is already on in `lib.rs`, with a `#[cfg(test)] extern crate std;` so the Appendix B trace test can
      print. The `alloc` feature is not started.
- [ ] Unit tests for everything added in this phase.

# Phase 5: Final Polish

- [ ] Complete the docs
    - `lib.rs` still starts with `//! TODO -- crate docs for AES` and `#![forbid(missing_docs)]` is commented out.
      QUALITY_AND_STYLE.md requires "Usage Examples", "Memory Usage" (a stack-usage table, so this needs the Phase 2
      benches) and "Security Considerations" -- the last is not optional here, or someone will use the raw engine as ECB.
    - Turning on `forbid(missing_docs)` will also flush out anything undocumented on the public surface.
- [ ] Clean up any `// TODO` comments left along the way
    - 34 at last count: 24 in `src/`, 10 in `tests/`. The `src/` ones cluster in `sbox.rs` (9, mostly "why is this
      broken out" and optimization notes) and `aes.rs` (7, the mode stubs). `sbox.rs:99` is already stale -- the
      exhaustive S-box test it asks for now exists.
- [ ] Check that Mutants is still happy
    - Not yet run for this crate. `.cargo/mutants.toml` examines `**/src/**/*.rs` and excludes `tests/**`, so the
      bc-test-data harnesses are not mutated but do run as part of the baseline.
- [ ] Get Claude to check against QUALITY_AND_STYLE.md
- [ ] Code review from other project members.
