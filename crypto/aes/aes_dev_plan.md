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
    - STATUS: `struct AES<KEY_LEN, Nr, Nroundkeys>` + the `AES128`/`AES192`/`AES256` aliases landed, and
      `rijndael.rs` is parametrized as described. Still outstanding: `KeySchedule` is a type alias, not a
      `struct` -- no streaming `.next_key()` and no `.pre_expand()`, and it is not `pub use`d.
- [x] How to model the state `s`? It would be sweet to impl something so that you can do `s[r,c] = x` and a
  `from<[u8;16]>` and `into<[u8;16]>` so that our source code will look extremely like the sample code and Table 1.
    - Resolved, but not with an indexing type: the state is a flat `[u8; 16]` laid out in Eq (3.6) order, so
      `state[r + 4c]` *is* `s[r, c]`, a column is a contiguous 4 bytes, and copying a block in or out is a plain
      16-byte copy. That made the `s[r,c]` sugar and the From/Into unnecessary. See the `state.rs` module docs.
- [ ] impl all the functions listed in 2.2 with the API exactly as listed, function bodies of a non-trivial length
  should be inline commented with the corresponding line (s) from the FIPS sample algs. (it doesn't need to stay this
  way, but provides a base for later optimization)
    - STATUS: everything in 2.2 except `EqInvCipher()` and `KeyExpansionEIC()` (which are the next item).
- [ ] There is good stuff in the nursery -- maybe it makes sense to mock out the function signatures we want, then go
  hunting for function bodies in the nursery?
- [X] Let's implement `EqInvCipher` after implementing the straightforward one so that we understand the perf-size
  tradeoffs that it represents, then we can decide whether to keep both or only keep one.
    - STATUS: Currently implemented but not declared yet
- [x] Consider side-channel implications, particularly of the sbox -- is it ok for this to be lookup-table based, or do
  we need to do something extra clever?
    - Not lookup-table based: `sbox.rs` evaluates the Boyar-Peralta-Calik `SLP_AES_113` Boolean circuit over a
      bitsliced state, so there is no secret-indexed memory access and no branching. The GF(2^8) multipliers in
      `state.rs` are branch-free for the same reason. Still to consider under this heading when the modes land:
      GHASH's GF(2^128) multiply has exactly the same table-lookup temptation.
- [ ] Basic Modes: CBC, GCM. (s. 6.5)
- [ ] Once working, go wrap everything in `Secret<>`.
    - STATUS: the round state in `cipher()`/`inv_cipher()` and every key schedule word are wrapped. The modes'
      chaining values and GHASH state will need it too.
- [x] Build basic unit tests as we go.
    - FIPS 197 Appendix A.1/A.2/A.3 (key schedule), Appendix B (`cipher()`/`inv_cipher()` end to end, plus
      `add_round_key()` on its own), and SP 800-38A F.1 known answers for all three key sizes through the public
      engine. 28 tests, no warnings. Filling these out to lock down *all* behaviours is Phase 2.

# Phase 2: Tests

- [ ] Fill out unit tests to lock down all behaviours. `cargo mutants` is very helpful at telling you when you're done.
  - STATUS: In progress with aes_tests.rs
- [ ] bc-test-data and wycheproof
- [ ] Create perf and mem benches

# Phase 3: De-duplication & Optimization

- [ ] De-duplicate code. Goal: reduce code review and test footprint by merging code where possible.
- [ ] Squeeze down perf & memory footprint.
- [ ] The parallelized SBox, can we increase it from u16 lanes to u64 lanes for more perf?
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
- [ ] Other modes:
    - Key Wrap (KW and KWP from SP 800-38F)
    - CMAC (SP 800-38B / RFC4493)
    - GMAC (SP 800-38D / RFC9044)
    - CCM? This is basically a standardized version of AES_CBC+MAC, but is strictly worse than AES_GCM, what I don't
      know is whether any protocols still use it, or if everything has moved to GCM.
- [ ] feature `hwaccel = ["avx", "aesni"]` -- add these as cargo features, maybe utilizing a new crate
  `bouncycastle-hwaccel` which holds all the unsafe and arch-specific assembly. (some of this might already exist in the
  nursery impl).
- [ ] `#[no_std]` and cargo `alloc` feature. Then start adding guards that `Box<>` stuff onto the heap when the `alloc`
  feature is enabled.
- [ ] Unit tests for everything added in this phase.

# Phase 5: Final Polish

- [ ] Complete the docs
- [ ] Clean up any `// TODO` comments left along the way
- [ ] Check that Mutants is still happy
- [ ] Get Claude to check against QUALITY_AND_STYLE.md
- [ ] Code review from other project members.