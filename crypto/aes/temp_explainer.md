# `crypto/aes` — what's here, what the TODOs mean, and how to finish Phase 1

*Working note, written 2026-08-13 against branch `feature/aes` (HEAD `7108c39`). Temporary — delete
once Phase 1 lands.*

---

## 1. Where the crate stands right now

In one sentence: **all four AES building blocks are written and individually tested, but nothing
joins them together, so no byte has ever actually been encrypted by this crate.**

`cargo test -p bouncycastle-aes` passes 19 tests. That sounds healthier than it is. Every one of
those tests exercises a *piece* — the S-box, ShiftRows, MixColumns, the key expansion — and none of
them exercises `cipher()` or `inv_cipher()`. Those two functions are dead code, which is why the
`#![allow(unused)]` in [lib.rs:8](src/lib.rs#L8) is currently load-bearing: it is the thing hiding
the fact that the top-level algorithm is never called.

And when you *do* call it, it panics. I temporarily added a test that calls
`cipher::<10>(&mut block, &w)` and it failed immediately:

```
thread 'rijnael::tmp_probe::tmp_call_cipher' panicked at crypto\aes\src\rijnael.rs:52:32:
index out of bounds: the len is 10 but the index is 10
```

(That probe has been reverted; the tree is clean.) Section 4 explains why.

So the honest status is: **~70% of the FIPS 197 arithmetic is done and well tested; 0% of the
plumbing is done.**

---

## 2. Map of the crate — file by file, in plain language

AES encrypts exactly 16 bytes at a time. Those 16 bytes are called the **state**. Encryption is 10,
12 or 14 **rounds** (depending on key size), and every round is the same four steps: scramble each
byte, shuffle the bytes around, mix them together, then XOR in a chunk of key. The files below are
one file per idea.

| File | What it is | Status |
|---|---|---|
| [lib.rs](src/lib.rs) | Crate root: module list + public exports | Skeleton |
| [aes.rs](src/aes.rs) | The numbers from FIPS 197 Table 3 (key lengths, round counts), key type aliases, and empty stubs for the CBC and GCM modes | Constants done, everything else empty |
| [sbox.rs](src/sbox.rs) | `SubBytes` — the byte-scrambling step, done as a bitsliced Boolean circuit | Done, well tested |
| [state.rs](src/state.rs) | `ShiftRows`, `MixColumns`, their inverses, and the GF(2⁸) multiply helpers | Done, well tested |
| [key_schedule.rs](src/key_schedule.rs) | `KeyExpansion` — turns one key into a long list of per-round key words | Done, tested against FIPS Appendix A |
| [rijnael.rs](src/rijnael.rs) | `Cipher` / `InvCipher` — the top-level loop that drives everything above, plus `AddRoundKey` | Written, broken, never called |

### 2.1 The state layout (worth understanding first, everything depends on it)

FIPS 197 draws the state as a 4×4 grid of bytes, `s[row, column]`, and fills it **down the columns**:
`s[r, c] = in[r + 4c]`. This crate stores it as a plain `[u8; 16]` in exactly that order, so
`state[r + 4*c]` *is* `s[r, c]`.

The payoff: a **column** is 4 bytes sitting next to each other (`state[4c .. 4c+4]`), and columns are
what MixColumns and AddRoundKey work on, so those two functions need no index gymnastics. The price:
a **row** is every 4th byte, and ShiftRows is the only thing that cares — so ShiftRows is written out
longhand, one row at a time. This is a good trade and it's documented at the top of
[state.rs](src/state.rs#L12-L31).

### 2.2 `sbox.rs` — the clever part

`SubBytes` replaces every byte with another byte from a fixed 256-entry table (FIPS 197 Table 4).
The obvious implementation is a lookup table — and the obvious implementation is a **security bug**,
because looking up `table[secret_byte]` puts the secret into the CPU's cache access pattern, which an
attacker sharing the machine can measure. This is the classic AES cache-timing attack.

So instead this crate evaluates the S-box as a **Boolean circuit** (the Boyar–Peralta–Çalık
`SLP_AES_113` circuit): 113 AND/XOR/XNOR gates, no branches, no memory indexing. Same answer, no
secret-dependent behaviour.

To make that fast it uses **bitslicing**: the 16 bytes of the state are transposed into 8 "planes"
of 16 bits each, where plane `i` holds bit `i` of all 16 bytes. Now one `plane[a] ^ plane[b]`
instruction does that XOR for all 16 bytes at once — you get all 16 S-box evaluations for roughly the
price of one. `bitslice()` transposes in, `unbitslice()` transposes back out.

Two wrinkles fall out of this and both show up as TODOs later:

- The key schedule needs the S-box on a **single 4-byte word**, not on 16 bytes. So
  [`sub_word()`](src/sbox.rs#L50) fakes it: it builds a 16-byte state that is 4 real bytes plus 12
  zero bytes, runs the whole circuit, and throws 12 bytes away.
- The published circuit leaves four output bits inverted, so
  [`sub_bytes_nots_bitsliced()`](src/sbox.rs#L353) applies four NOTs afterwards — and, because
  decryption has to undo things in reverse order, `inv_sub_bytes` applies them *first*. It's correct,
  but it means every caller has to remember an ordering rule.

### 2.3 `state.rs` — the ordinary parts

- **ShiftRows**: row 0 stays put, row 1 rotates left 1, row 2 left 2, row 3 left 3. Written out by
  hand so no second copy of the state is created (a copy is a copy of secret data).
- **MixColumns**: each column of 4 bytes is multiplied by a fixed 4×4 matrix, using "multiplication"
  in GF(2⁸) — finite-field arithmetic where addition is just XOR.
- **The multipliers** `mul_02`, `mul_03`, `mul_09`, `mul_0b`, `mul_0d`, `mul_0e`: the cipher only ever
  multiplies by those six fixed values, so each is a short hard-coded chain of `xtimes()` (multiply
  by 2) and XOR. `xtimes()` is branch-free — it computes both cases and selects with a mask — for
  the same timing reason as the S-box. The comment there saying "do not simplify this back into an
  `if`" is serious.
- `gf_mul` / `gf_pow` are `#[cfg(test)]` only, deliberately: they *do* branch on secret bits and
  exist purely to cross-check the fixed multipliers.

### 2.4 `key_schedule.rs` — turning one key into many

One key (16/24/32 bytes) is stretched into a list of 32-bit words: 44 for AES-128, 52 for AES-192,
60 for AES-256. That's `4 * (Nr + 1)` words = 4 words for each of the `Nr + 1` AddRoundKey calls.

The recurrence is a direct transcription of FIPS 197 Algorithm 2: copy the key in as the first `Nk`
words, then each later word is the word `Nk` back, XORed with the previous word — with an extra
scramble (`RotWord` + `SubWord` + a round constant) every `Nk` words, plus one more `SubWord` case
that only AES-256 hits. The three tests reproduce FIPS 197 Appendices A.1/A.2/A.3 word for word.
**This part is genuinely finished and trustworthy.**

### 2.5 `rijnael.rs` — the conductor

`cipher()` is Algorithm 1, line for line, with the FIPS pseudocode line numbers in the comments:
initial AddRoundKey, then `Nr - 1` full rounds, then a final round that skips MixColumns.
`inv_cipher()` is Algorithm 3 the same way. Both hold the working state in a
`Secret<[u8; 16]>`, so intermediate rounds get scrubbed from memory on the way out. The structure is
right. The wiring is not — see next section.

(The filename is a typo: it should be `rijndael.rs`, and `aes_dev_plan.md` calls it that.)

---

## 3. How a single block *would* flow, once it works

```
key ──► key_expansion() ──► w: 44/52/60 words
                                  │
plaintext block ──► state ────────┼──► AddRoundKey(w[0..4])
                                  │
                         repeat Nr-1 times:
                                  │    sub_bytes()      (sbox.rs, bitsliced circuit)
                                  │    shift_rows()     (state.rs)
                                  │    mix_columns()    (state.rs)
                                  │    AddRoundKey(w[4r .. 4r+4])
                                  │
                         final round (no mix_columns):
                                  │    sub_bytes() ; shift_rows() ; AddRoundKey(w[4Nr .. 4Nr+4])
                                  ▼
                            ciphertext block
```

Decryption is the same picture reversed, with `inv_` versions and the round keys consumed
back-to-front.

---

## 4. The join that isn't joined — three concrete defects

These are not "TODO comments", they are bugs sitting in the code today. They're the substance of
"get all the bits and pieces connected".

**(a) A round key is 4 words, but the type says 1 word.**
[key_schedule.rs:10](src/key_schedule.rs#L10) defines `type RoundKey = Secret<u32>` — a single 32-bit
word. But FIPS 197 §5.1.4 defines a round key as **four** words (16 bytes), one per column of the
state. The doc comment right above it says "four words (ie four bytes)", which is where the confusion
crept in — four words is sixteen bytes.

**(b) `add_round_key()` XORs the same word into all four columns.**
[rijnael.rs:93-102](src/rijnael.rs#L93-L102) takes one `RoundKey` (one word) and XORs it into columns
0, 1, 2 and 3 identically. FIPS 197 Eq (5.9) says column `c` gets word `w[4*round + c]` — four
*different* words. This produces wrong ciphertext, not just inelegant code.

**(c) `cipher()` asks for the wrong-sized schedule and reads off the end of it.**
[rijnael.rs:22](src/rijnael.rs#L22) is `fn cipher<const Nr: usize>(block, w: &KeySchedule<Nr>)`. But
`KeySchedule<N>` is parameterised by the *number of words*, not the number of rounds — so
`KeySchedule<Nr>` is an array of 10 words when it should be 44. The function then indexes `w[Nr]`,
i.e. `w[10]` of a 10-element array. That's the panic in section 1. Rust can't catch it at compile
time because `Nr` is generic, so it survives until the first call.

There's a naming trap feeding this: `Nroundkeys` in
[aes.rs:29-33](src/aes.rs#L29-L33) counts **words**, not round keys. For AES-128 it's 44 — but there
are only 11 round keys. Renaming it (`AES128_KEY_SCHEDULE_WORDS` is what the older branch called it)
removes the whole class of confusion.

**Plus: nothing can reach any of this.** `key_expansion()` is private with no public constructor,
there is no `AES128`/`AES192`/`AES256` engine type, and `cipher()`/`inv_cipher()` are private. The doc
comments in `aes.rs` already link to `[AES128::new]`, which doesn't exist — those are broken
intra-doc links waiting for `#![forbid(missing_docs)]` to be switched on.

---

## 5. The TODO inventory

There are 29 `TODO`/`todo` comments in `crypto/aes`. Here they are, grouped by what they actually
demand of you. **Split: 10 block Phase 1, 11 are cleanup that Phase 1 should sweep up, 8 are
deliberate deferrals to Phases 2–5 and should be left alone for now.**

### 5.1 Blocking — Phase 1 is not done until these are

| Where | TODO | Why it matters |
|---|---|---|
| [aes.rs:44,55,59,69,73](src/aes.rs#L44) | `AES_CBC` and `AES_GCM` structs are empty; the `impl BlockCipher`/`impl AEADCipher` blocks are commented out | This is the "implement AES_CBC and AES_GCM" chunk. Also note there is no engine type for them to wrap yet. |
| [key_schedule.rs:41](src/key_schedule.rs#L41) | "do KeyType and SecurityStrength checks on key. That'll mean returning a Result" | This is the crate's only legitimate failure mode. Per house style, key validation belongs in a constructor (`AES128::new`) that returns `Result`, so the per-block functions can stay infallible. Do this *at the same time* as introducing the engine type, not after. |
| [lib.rs:7](src/lib.rs#L7) | `#![allow(unused)]` "here only to suppress warnings during dev. Remove once crate is complete" | Delete this early, not last. Right now it is actively concealing that `cipher()`, `inv_cipher()`, `rot_word_coreys_way` and `sub_bytes_nots_bitsliced` are unreachable. Removing it turns "connect the bits" into a compiler-driven checklist. |
| [lib.rs:1](src/lib.rs#L1) | Crate docs | QUALITY_AND_STYLE requires "Usage Examples", "Memory Usage" and "Security Considerations" sections. The Security Considerations section is not optional here — someone will otherwise use the raw engine as ECB. |
| [lib.rs:5](src/lib.rs#L5) | Turn on `#![forbid(missing_docs)]` | Turn it on once the public surface stops moving; it will also flush out the broken `[AES128::new]` doc links. |
| [sbox.rs:99](src/sbox.rs#L99) | "unit test `inv_sub_bytes` by feeding in 16 bytes of Table 4" | **Arguably already done** by `sbox_tests::test_sub_bytes`, which round-trips both directions — *except* that test has a coverage bug, see 5.4 below. Fix the bug, then tick this off. |

### 5.2 Cleanup — the "delete code we didn't need" chunk

| Where | TODO | Recommendation |
|---|---|---|
| [state.rs:33](src/state.rs#L33) | "move the functions that are used into `rijnael.rs` and delete this file" | Agreed in spirit, but `state.rs` is ~200 lines of real transformations plus the GF multipliers. Merging all of it into `rijnael.rs` makes one big file. **Suggestion: keep the split, but rename** — `rijnael.rs` → `rijndael.rs` (fix the typo) holding the two Algorithms, and `state.rs` keeping the four transformations, which is what its module doc already describes. Then delete only what's genuinely surplus (next three rows). |
| [state.rs:46,56](src/state.rs#L46) | `sub_bytes`/`inv_sub_bytes` in `state.rs` "are literally a passthrough — why is this useful?" | They aren't useful. Delete both and have `rijndael.rs` call `sbox::sub_bytes` directly. |
| [rijnael.rs:111](src/rijnael.rs#L111) | `rot_word_coreys_way()` — a second implementation of `rot_word` as `word.rotate_left(8)` | Pick one and delete the other. `rotate_left(8)` is the better one: one instruction, and provably the same thing. Keep the FIPS Eq (5.10) comment on whichever survives. |
| [sbox.rs:39](src/sbox.rs#L39) | "should `type State` move to `state.rs`?" | Yes — one definition of the state type, in the module named after it. |
| [state.rs:206](src/state.rs#L206) | "not convinced we need the tutorial text above" | Agreed, it restates FIPS §4. Cut it to a few lines and a section reference; keep the security paragraph about why there's no general multiply. |
| [sbox.rs:85,189,351](src/sbox.rs#L85) | "why are the 4 NOTs a separate function? Can we fold them in?" (asked three times) | Yes, fold them into `sub_bytes_bitsliced` / `inv_sub_bytes_bitsliced` with an inline comment noting the deviation from `SLP_AES_113.txt`. It removes an ordering rule that callers currently have to remember. Do it *after* the Appendix B test passes, so you have a safety net. |
| [sbox.rs:197](src/sbox.rs#L197) | "reserve 🚨 for actual security considerations" | Trivial. The 🚨 in `state.rs:202` (constant-time multiply) is legitimate; the one at `sbox.rs:188` is not. |
| [sbox.rs:116](src/sbox.rs#L116) | `bitslice()` returns a new array while `unbitslice()` writes into an out-param — "make them the same" | Make both write into an out-param, or document why not. Minor, but it's a secret-data copy, so it's worth being deliberate. |
| [state.rs:353](src/state.rs#L353) | "Link? Where did these test vectors come from?" | They're from NIST's "AES Core" ECB-AES128 intermediate-value file. Add the URL, or replace them with FIPS 197 Appendix B values, which are in-repo (see §6.2). |

### 5.3 Deliberate deferrals — leave these alone in Phase 1

These are all "measure before optimising" notes and belong to Phases 3–4. Resist them; they're the
kind of thing that eats a week and can't be validated until benches exist.

- [rijnael.rs:26](src/rijnael.rs#L26) — encrypt in place instead of copying to a `Secret` state (saves
  16 bytes, may cost speed). Needs a before/after benchmark. **Phase 3.**
- [key_schedule.rs:70](src/key_schedule.rs#L70) — replace `%` and `/` on the loop counter with
  counters. Correctly notes there's no constant-time concern (the counter isn't secret). **Phase 3.**
- [sbox.rs:57](src/sbox.rs#L57) — a `bitslice_word()` that avoids shuffling 12 zero bytes in
  `sub_word()`. Self-describes the gain as "probably negligible". **Phase 3.**
- [sbox.rs:217](src/sbox.rs#L217) — does the 113-`let` circuit really use 226 bytes of stack, or is
  LLVM smarter? Explicitly says to hold off until there are memory benches. **Phase 3.**
- [sbox.rs:148](src/sbox.rs#L148) — find a citable academic paper for the S-box circuit rather than
  just the `.txt`. **Phase 5 (docs).**
- [state.rs:326](src/state.rs#L326) — "are all these tests necessary? Do they cost CI runtime?"
  **Phase 2**, and partly answered by §6.2: once Appendix B passes end to end, several
  per-transformation tests become redundant.
- [aes.rs:48,76](src/aes.rs#L48) — the other modes (CTR, CCM, KW/KWP, CMAC, GMAC). Already recorded in
  `aes_dev_plan.md` Phase 4. **Not Phase 1.**

### 5.4 One thing that isn't marked TODO but should be

[`sbox_tests::test_sub_bytes`](src/sbox.rs#L603) says *"that's an exhaustive test of correctness"* and
it isn't. It loops `i in 0..16` over `DUMMY_SEED[i..i+16]`, and since `DUMMY_SEED[i] == i`, that
covers input bytes `0x00..=0x1f` — 31 of 256 values, each tested several times. The intent (stated in
its own comment: "invoke it 16 times to test all 256 possible input values") needs the slice to be
`DUMMY_SEED[16*i .. 16*i+16]`, compared against `sbox_lookup_table[16*i .. 16*i+16]`. One-character
class of fix, and then the claim is true and `sbox.rs:99` can be ticked off.

---

## 6. The development plan for finishing Phase 1

Three chunks, in this order. The ordering matters: cleanup is much safer once an end-to-end test
exists, so **don't** start with the deletions.

### 6.0 Before anything: raid the nursery

`aes_dev_plan.md` line 19 asks: *"There is good stuff in the nursery — maybe it makes sense to mock
out the function signatures we want, then go hunting for function bodies in the nursery?"*

The nursery is the branch **`feature/officialfrancismendoza/64-AES-block-cipher-engine`**, and it is
much further along than this branch on exactly the parts that are missing here:

```
crypto/aes/src/aes.rs           ← AES<KEY_LEN, NR, W_WORDS> engine, AESEngine trait,
                                  new() with key validation, cipher(), inv_cipher(),
                                  a correct add_round_key(state, w, round)
crypto/aes/src/key_schedule.rs  ← key_expansion::<KEY_LEN, W_WORDS>()
crypto/aes/tests/aes_tests.rs   ← FIPS 197 Appendix B test + AES-128/192/256 KATs +
                                  avalanche, round-trip and key-rejection tests
crypto/aes/tests/wycheproof.rs
crypto/aes/benches/aes_benches.rs
```

Its `add_round_key` is the correct four-word version, and its `cipher()`/`inv_cipher()` are
structurally identical to the ones on this branch — this branch's versions look like they were
derived from them and lost the round indexing on the way. Diff the two branches file by file before
writing anything new. Realistically this saves several days and most of the test-writing.

What this branch has that the nursery doesn't: the bitsliced constant-time S-box (the nursery uses a
`tables.rs` lookup table). That is the reason this branch exists, and it answers `aes_dev_plan.md`
line 23's side-channel question — so keep this branch's `sbox.rs` and import the plumbing around it.

### 6.1 Chunk 1 — connect the bits, then pin it with FIPS 197 Appendix B

**Step 1 — delete `#![allow(unused)]`.** The resulting warning list is your worklist.

**Step 2 — fix the round-key model.** One decision drives everything else:

> Is the key schedule an array of *words* that `add_round_key` indexes into (`w[4*round + c]`), or an
> array of *round keys* where each element is `[u32; 4]`?

Recommendation: **array of words**, matching both FIPS 197 and the nursery. It keeps the AES-192
case simple (the schedule boundary doesn't line up with `Nk`) and matches the streaming key schedule
sketched in `aes_dev_plan.md`. Concretely:

- rename `Nroundkeys` → `AES*_KEY_SCHEDULE_WORDS` (it counts words, not round keys);
- `add_round_key(state, w, round)` takes the whole schedule plus a round number, and XORs
  `w[4*round + c]` into column `c`;
- `cipher`/`inv_cipher` become generic over both `NR` and `W_WORDS` until `generic_const_exprs`
  stabilises (the dev note in `key_schedule.rs` already anticipates this).

**Step 3 — add the engine type.** `struct AES<const KEY_LEN, const NR, const W_WORDS>` with the three
Table 3 aliases `AES128`/`AES192`/`AES256`, a `new(&KeyMaterial<KEY_LEN>) -> Result<Self, _>` that
does the KeyType/SecurityStrength validation (closing `key_schedule.rs:41`), and infallible
`encrypt_block`/`decrypt_block`. Validation in the constructor, no `Result` on the per-block calls —
that's the "push errors to compile time" rule, and it's what the nursery already does.

Seal the valid parameter sets the way the nursery did: put `where Self: Algorithm` on the impl blocks
and implement `Algorithm` only for the three aliases. The orphan rule then makes a fourth
(non-standard) parameter set impossible to construct from outside the crate.

**Step 4 — the Appendix B test.** FIPS 197 Appendix B is the AES-128 worked example:

```
Input = 32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34
Key   = 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
Out   = 39 25 84 1d 02 dc 09 fb dc 11 85 97 19 6a 0b 32
```

(The output is read down the columns of the `output` state grid on p.35 of the PDF — the same
column-major convention as §2.1 above, so it drops straight into a `[u8; 16]`.) The key is the same
one already used by the `appdx_a1` key-schedule test, so the two tests reinforce each other.

Write it as two assertions — `cipher()` gives the expected ciphertext, and `inv_cipher()` on that
ciphertext gives the plaintext back. Put it in `tests/aes_tests.rs` (a new file) driving the public
`AES128` API, not as an in-file unit test — it's testing the public surface, which is what
QUALITY_AND_STYLE prefers.

Worth doing while you're there, because it's nearly free: the Appendix B table also lists the state
after *every* transformation of *every* round. A `#[cfg(test)]` trace check against a couple of those
intermediate rows turns "wrong answer" into "wrong answer, first diverging at round 4 MixColumns",
which is the difference between a ten-minute debug and a two-day one. This is also what lets you
retire the ad-hoc NIST intermediate values in `state.rs` (`state.rs:353`).

**Step 5 — AES-192 and AES-256.** Appendix B only covers AES-128. Add one known-answer vector for
each of the other two (the nursery's `aes_tests.rs` has them, sourced from the NIST ECB vector files
that pair with SP 800-38A Appendix F.1) — otherwise the `Nk > 6` branch in the key schedule and the
12/14-round loops are only covered by the key-schedule tests, not end to end.

### 6.2 Chunk 2 — cleanup

Do this *after* 6.1 is green, so every deletion is protected by a test. Work through §5.2 in that
order. The Appendix B + KAT tests also let you answer `state.rs:326` ("are all these tests
necessary?") with evidence: once the full cipher is pinned, the per-transformation NIST
intermediate-value tests are largely redundant and can go. Keep the ones that test properties an
end-to-end vector *cannot* catch:

- `every_transformation_round_trips` (covers the all-zero and all-ones degenerate states),
- `fixed_multipliers_match_general_multiplication` (all 256 inputs × 6 multipliers),
- `shift_rows_permutes_within_rows_only` and `mix_columns_keeps_columns_independent` (structural
  properties — these are exactly the tests that kill mutants in Phase 2),
- `sbox_tests::test_sub_bytes`, **after** fixing the coverage bug in §5.4.

Also fold in the small structural items: rename `rijnael.rs` → `rijndael.rs`, delete
`rot_word_coreys_way`, delete the two passthrough wrappers, move `type State` into `state.rs`.

### 6.3 Chunk 3 — AES_CBC and AES_GCM

**First, a scope decision that needs your call.** There's a recorded decision (from the nursery
branch) that `crypto/aes` should be the raw permutation only, with modes living in their own crates,
because the core cipher traits are about encrypting *data* — they generate IVs, handle padding and
authenticate — and none of that belongs to a 16-byte permutation. The current branch instead has
`AES_CBC`/`AES_GCM` stubbed inside `crypto/aes/src/aes.rs`.

Both work. The two options:

- **(a) Modes inside `crypto/aes`** — fewer crates, simplest thing that satisfies the request. The
  raw `AES128`/`AES192`/`AES256` engine still must *not* implement `SymmetricCipher`/`BlockCipher`
  (see below for why), so you'd have one crate exporting both a raw engine and two mode types.
- **(b) Modes in `crypto/aes-cbc` and `crypto/aes-gcm`** — matches the recorded decision and the NIST
  CSOR model, where OIDs are assigned per mode and never to the bare cipher. More Cargo boilerplate.

I'd go with **(a) for now** — it's what the stubs already assume and it keeps Phase 1 short — and
split later if the file gets unwieldy. Either way, the hard constraint holds: **do not implement the
cipher traits on the raw engine.** The only mode a raw engine can offer is ECB, and implementing
`SymmetricCipher` on it would publish an ECB one-shot as the crate's headline API. There's also a
mechanical blocker: `core-test-framework`'s `TestFrameworkBlockCipher` asserts
`assert_ne!(iv1, iv2)` across two `do_encrypt_init()` calls, which a zero-length-IV engine can never
satisfy. A real CBC mode with a random 16-byte IV satisfies it fine.

**Prerequisite for both modes: an RNG dependency.** `SymmetricCipher::encrypt_out` and
`AEADCipher::aead_encrypt_out` both *generate* the IV/nonce internally and return it. That means
`crypto/aes/Cargo.toml` needs `bouncycastle-rng` as a runtime dependency, calling
`HashDRBG_SHA512::new_from_os()` — the same pattern ASCON and ML-KEM already use. This is the one
place Phase 1 adds a runtime dep, so flag it in review.

#### AES_CBC (SP 800-38A §6.2)

Simple in concept: XOR each plaintext block with the previous ciphertext block before encrypting;
the first block uses a random IV.

```
C[0] = CIPHER(P[0] XOR IV)
C[i] = CIPHER(P[i] XOR C[i-1])
```

Decryption is `P[i] = INVCIPHER(C[i]) XOR C[i-1]`, which is where `inv_cipher()` finally earns its
keep. Implementation notes:

- Trait shape: `SymmetricCipher<KEY_LEN, 16>` + `BlockCipher<KEY_LEN, 16, 16>` — `INIT_DATA_LEN` is
  the 16-byte IV.
- State to carry: the engine (holding the key schedule) plus the 16-byte chaining value. The chaining
  value is not secret in the same way the key is, but wrap it in `Secret<>` anyway; it's cheap.
- **Padding is a decision.** SP 800-38A's CBC is defined only for whole blocks. The `BlockCipher`
  trait's `do_encrypt_final`/`do_decrypt_final` split exists precisely so a mode can add/strip
  padding at the end. PKCS#7 is the near-universal choice. Note the trait signature takes a full
  `[u8; BLOCK_LEN]` for the final block, so partial trailing data has to be handled by the caller or
  by the one-shot — worth checking against how ASCON resolved the same signature before committing.
- 🚨 **Padding oracles.** On decrypt, "is the padding valid?" must not be answerable by timing.
  Validate with the constant-time helpers in `bouncycastle_utils::ct` rather than an early-returning
  loop. This is the single most likely place for a real vulnerability in Phase 1.

#### AES_GCM (SP 800-38D)

Substantially more work than CBC — realistically the largest single item left in Phase 1. Two
machines bolted together:

1. **CTR mode for confidentiality.** Encrypt a counter block, XOR into the plaintext. Only ever calls
   `cipher()`, never `inv_cipher()` — so GCM decryption uses the *forward* permutation too.
2. **GHASH for authentication.** A polynomial MAC over GF(2^128), keyed by `H = CIPHER(0^128)`,
   absorbing the AAD, then the ciphertext, then a length block.

Order of work:

- `H = CIPHER(0^128)`; derive `J0` from the nonce (for the standard 12-byte nonce, `J0 = nonce ||
  0x00000001`; other lengths go through GHASH, so implement the 12-byte case first and handle the
  rest once the KATs pass).
- CTR encryption starting at `inc32(J0)`.
- GHASH over `AAD || pad || C || pad || [len(AAD)]64 || [len(C)]64`.
- `Tag = GHASH_result XOR CIPHER(J0)`; on decrypt, compare with a **constant-time** equality check
  (`bouncycastle_utils::ct`) and return `SymmetricCipherError::AEADTagCheckFailed` on mismatch —
  never return plaintext alongside a failed tag.
- Trait shape: `AEADCipher<KEY_LEN, 12, 16>` — 12-byte nonce, 16-byte tag — plus the
  `SymmetricCipher<KEY_LEN, 12>` supertrait.

🚨 **The GF(2^128) multiply in GHASH has the same cache-timing problem as the S-box did.** The fast
textbook implementation uses precomputed tables indexed by secret data. Given this crate went to the
trouble of a bitsliced constant-time S-box, a table-driven GHASH would be an odd thing to ship
alongside it. Plan for a branch-free, index-free carry-less multiply and accept the speed cost in
Phase 1; revisit under Phase 4's `hwaccel` feature (`pclmulqdq`/`vmull`), which is what makes GCM
fast in practice anyway.

**Testing the modes:** run both through `core-test-framework`'s `symmetric_ciphers.rs` harness (that
is the house rule for anything implementing a core trait), plus NIST vectors — SP 800-38A Appendix F
for CBC, and the NIST GCM validation vectors for GCM.

### 6.4 What to tick off in `aes_dev_plan.md`

My read of the current state, for when you go through that file:

| Phase 1 item | Status |
|---|---|
| Start with `rijndael.rs`, `key_schedule.rs`, then `aes.rs`; one `struct AES<..>` | Partly — files exist, the `struct AES<..>` does not |
| How to model the state `s`? | **Done** — the flat `[u8; 16]` column-major layout, documented in `state.rs`. The `s[r,c]` indexing sugar was deliberately not built, because the flat layout made it unnecessary; worth writing that down as the answer rather than leaving it open |
| impl all the functions in §2.2 with the FIPS API and line-by-line comments | Nearly — every §2.2 function exists except the mode-level ones; the comment discipline is genuinely good |
| Go hunting in the nursery | Not started — see §6.0, this is the highest-leverage item left |
| `EqInvCipher` after the straightforward one | Not started, and it is **not** Phase 1 work. The nursery's `inv_cipher` already documents the tradeoff (EqInvCipher needs a second INVMIXCOLUMNS-transformed key schedule, so it trades memory for round-structure symmetry). Decide in Phase 3 with benches |
| Side-channel implications of the S-box | **Done, and it's the best thing on this branch** — bitsliced Boolean circuit, no lookup, no branching. Tick it and note the GHASH equivalent is still outstanding |
| Basic modes: CBC, GCM | Not started — §6.3 |
| Wrap everything in `Secret<>` | Partly — the state and round keys are wrapped; the modes' chaining values and GHASH state will need it too |
| Build basic unit tests as we go | Partly — excellent per-piece coverage, zero end-to-end coverage |

---

## 7. Suggested order of work

1. Diff against the nursery branch; decide what to lift. *(§6.0)*
2. Remove `#![allow(unused)]`; fix the round-key model and `add_round_key`. *(§6.1 steps 1–2)*
3. Add the `AES<..>` engine + `new()` with key validation. *(§6.1 step 3)*
4. **FIPS 197 Appendix B test passes.** ← the milestone that turns this from parts into a cipher
5. AES-192 / AES-256 known-answer tests. *(§6.1 step 5)*
6. Cleanup sweep. *(§6.2)*
7. AES_CBC. *(§6.3)*
8. AES_GCM. *(§6.3)*
9. Crate docs + `#![forbid(missing_docs)]`; tick off `aes_dev_plan.md`.

Steps 1–5 are the risky, order-dependent part; after step 4 everything else is protected by a test.

## 8. Open questions for you

1. **Modes here or in their own crates?** (§6.3). I've assumed here, per the existing stubs.
2. **Is taking a runtime dependency on `bouncycastle-rng` acceptable for this crate?** It's forced by
   the core traits' internally-generated IV/nonce, but it's the first non-`core`/`utils` runtime dep
   this crate would have.
3. **CBC padding: PKCS#7, or whole-blocks-only with padding pushed to the caller?**
4. **Keep `state.rs` as its own file** (my suggestion), or follow the `state.rs:33` TODO and merge
   everything into `rijndael.rs`?
