use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait};
use bouncycastle_utils::secret::Secret;

use crate::rijnael::*;

/// Implements the interface described in section 5.2 to obtain the (Nr + 1) round keys
/// The reason for having a trait is that multiple types of key schedule implementations are supported:
///   * An up-front computation of all (Nr + 1) keys following the Algorithm 2 KeyExpansion()
///   * A streaming API where keys are generated on-demand (smaller memory footprint)
///
/// Constants (inherited from super):
/// Nk: The number of 32-bit words comprising the key. Nk is assigned
///     to 4, 6, and 8 for AES-128, AES-192, and AES-256, respectively.
///
/// Nr: The number of rounds. Nr is assigned to 10, 12, and 14 for
///     AES-128, AES-192, and AES-256, respectively.
///
/// This is a private trait (aka private bound) so that the bc-rust AES implementation
/// can accept multiple implementations of the KeySchedule interchangeably, but users outside
/// the library cannot implement their own.
//
// Dev note: Once the const_generic_exprs feature lands in rust stable, then we'll be able to delete
//           `const KEY_LEN` and instead do `KeyMaterial<{Nk*4}>`.
trait KeySchedule<const Nk: usize, const Nr: usize, const KEY_LEN: usize>: Sized {
    fn init(key: &KeyMaterial<KEY_LEN>) -> Self;

    // todo -- figure out how to make this Secret<[u32; 4]> ?
    //         may need to add a slice feature to the Secret class
    fn next_key(&mut self) -> Secret<[u32; Nk]>;
}

/// Round Constants
///
/// Table 5. Round constants
/// j Rcon\[j] j Rcon\[j]
/// 1 \[01,00,00,00] 6 \[20,00,00,00]
/// 2 \[02,00,00,00] 7 \[40,00,00,00]
/// 3 \[04,00,00,00] 8 \[80,00,00,00]
/// 4 \[08,00,00,00] 9 \[1b,00,00,00]
/// 5 \[10,00,00,00] 10 \[36,00,00,00]
///
/// Note: FIPS 197 uses a 1-based index IE `Rcon[j]` for j=1 to j=10,
///       but to not waste space, we will use a 0-based index j=0 .. 9
// TODO -- need to look again at the little-endian description in section 3
const Rcon: [u32; 10] = [
    u32::from_le_bytes([0x01, 0x00, 0x00, 0x00]),
    u32::from_le_bytes([0x02, 0x00, 0x00, 0x00]),
    u32::from_le_bytes([0x04, 0x00, 0x00, 0x00]),
    u32::from_le_bytes([0x08, 0x00, 0x00, 0x00]),
    u32::from_le_bytes([0x10, 0x00, 0x00, 0x00]),
    u32::from_le_bytes([0x20, 0x00, 0x00, 0x00]),
    u32::from_le_bytes([0x40, 0x00, 0x00, 0x00]),
    u32::from_le_bytes([0x80, 0x00, 0x00, 0x00]),
    u32::from_le_bytes([0x1b, 0x00, 0x00, 0x00]),
    u32::from_le_bytes([0x36, 0x00, 0x00, 0x00]),
];

/// Generating the AES key schedule is a computationally expensive operation.
/// This implementation of the KeySchedule fully computes the full key schedule up-front and stores it
/// in order to make the encrypt and decrypt operations faster.
///
/// This struct has a memory footprint of `4 * (Nr + 1) * 4` bytes for the key schedule plus a counter,
/// which works out to:
/// * AES-128: X bytes
/// * AES-192: X bytes
/// * AES-256: X bytes
/// TODO -- complete these numbers
///
// Dev note: The number of words for a fully expanded key schedule is `4 ∗ (Nr + 1)`, which unfortunately
//           needs to be its own constant separate from `Nr` until the `const_generic_exprs` feature hits
//           rust stable.
struct PreExpandedKeySchedule<
    const Nk: usize,
    const Nr: usize,
    const KEY_LEN: usize,
    const KEY_SCHEDULE_SIZE: usize,
> {
    w: Secret<[u32; KEY_SCHEDULE_SIZE]>,
    /// The round counter for how many keys have been given out via [KeySchedule::next_key].
    i: usize,
}

impl<const Nk: usize, const Nr: usize, const KEY_LEN: usize, const KEY_SCHEDULE_SIZE: usize>
    PreExpandedKeySchedule<Nk, Nr, KEY_LEN, KEY_SCHEDULE_SIZE>
{
    /// Algorithm 2 KeyExpansion(key)
    ///
    /// Also serves as the constructor and init for the [PreExpandedKeySchedule] struct.
    ///
    /// Constants (inherited from super):
    /// Nk: The number of 32-bit words comprising the key. Nk is assigned
    ///     to 4, 6, and 8 for AES-128, AES-192, and AES-256, respectively.
    ///
    /// Nr: The number of rounds. Nr is assigned to 10, 12, and 14 for
    ///     AES-128, AES-192, and AES-256, respectively.
    ///
    /// This is an internal non-pub fn so we assume that the public [KeySchedule::init] has already performed
    /// all the necessary checks on the input key.
    fn KeyExpansion(key: &[u8]) -> Self {
        let mut key_schedule = Self { w: Secret::<[u32; KEY_SCHEDULE_SIZE]>::new(), i: 0 };

        // The first Nk words of the expanded key are the key itself.
        // 2: i ← 0
        // 3: while i ≤ Nk − 1 do
        // 4:   w[i] ← key[4 ∗ i..4 ∗ i + 3]
        // 5:   i ← i + 1
        // 6: end while ▷ When the loop concludes, i = Nk.
        for i in 0..Nk {
            key_schedule.w[i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
        }

        // Every subsequent word w[i] is generated recursively from the
        // preceding word, w[i − 1], and the word Nk positions earlier, w[i − Nk], as follows:
        // 7: while i ≤ 4 ∗ Nr + 3 do
        for i in Nk..4 * Nr + 4 {
            // 8:   temp ← w[i − 1]
            let mut temp = key_schedule.w[i - 1];

            // TODO Optimization note: the `i mod Nk` will trigger at fixed points in the computation.
            //      Once this is working, use Godbolt to check how this gets compiled. I hope it gets
            //      compiled unrolled and does not actually have a conditional jump here.
            //      If it's not unrolled, then we should build unrolled versions for -128, -196, -256 and
            //      see if there's a perf difference.
            // 9:   if i mod Nk = 0 then
            // 10:      temp ← SubWord(RotWord(temp)) ⊕ Rcon[i/Nk]
            if i % Nk == 0 {
                // TODO: there's probably a way to optimize either structurally or with a counter to not need the int division
                temp = SubWord(RotWord(temp)) ^ Rcon[i / Nk];
            }

            // todo finish this
            // Nk > 6 is only true for AES-256
            // 11:  else if Nk > 6 and i mod Nk = 4 then
            // 12:      temp ← SubWord(temp)
            // 13:  end if
            // 14:  w[i] ← w[i − Nk] ⊕ temp
            // 15:  i ← i + 1
            // 16: end while
        }

        // 17: return w
        key_schedule
    }
}

impl<const Nk: usize, const Nr: usize, const KEY_LEN: usize, const KEY_SCHEDULE_SIZE: usize>
    KeySchedule<Nk, Nr, KEY_LEN> for PreExpandedKeySchedule<Nk, Nr, KEY_LEN, KEY_SCHEDULE_SIZE>
{
    fn init(key: &KeyMaterial<KEY_LEN>) -> Self {
        // todo -- check KeyType and SecurityStrength. I guess this will need to return a Result?

        Self::KeyExpansion(key.ref_to_bytes())
    }

    fn next_key(&mut self) -> Secret<[u32; Nk]> {
        // First, check that we haven't exhausted the key schedule.
        // Since this is not a pub fn, a panic here is a logic error within the library implementation,
        // so we'll only check for this in test mode.
        #[cfg(test)]
        if self.i > Nr + 1 {
            panic!("Key schedule exhausted");
        }

        self.i += 1;
        (*self.w)[(self.i - 1) * Nk..self.i * Nk].try_into().unwrap()
    }
}

/// This implementation of the KeySchedule operates in a streaming mode to optimize for a small
/// memory footprint.
///
/// This struct has a memory footprint of `Nk` bytes for the current state of the key schedule plus a counter,
/// which works out to:
/// * AES-128: X bytes
/// * AES-192: X bytes
/// * AES-256: X bytes
/// TODO -- complete these numbers
///
// Dev note: The number of words for a fully expanded key schedule is `4 ∗ (Nr + 1)`, which unfortunately
//           needs to be its own constant separate from `Nr` until the `const_generic_exprs` feature hits
//           rust stable.
struct StreamedKeySchedule<
    const Nk: usize,
    const Nr: usize,
    const KEY_LEN: usize,
    const KEY_SCHEDULE_SIZE: usize,
> {
    state: Secret<[u32; Nk]>,
    /// The round counter for how many keys have been given out via [KeySchedule::next_key].
    i: usize,
}

impl<const Nk: usize, const Nr: usize, const KEY_LEN: usize, const KEY_SCHEDULE_SIZE: usize>
    KeySchedule<Nk, Nr, KEY_LEN> for StreamedKeySchedule<Nk, Nr, KEY_LEN, KEY_SCHEDULE_SIZE>
{
    fn init(key: &KeyMaterial<KEY_LEN>) -> Self {
        // todo -- check KeyType and SecurityStrength. I guess this will need to return a Result?

        let mut key_schedule = Self { state: Secret::<[u32; Nk]>::new(), i: 0 };

        // Just load the key into the state.
        // This corresponds to
        //
        // Algorithm 2 KeyExpansion(key)
        // The first Nk words of the expanded key are the key itself.
        // 2: i ← 0
        // 3: while i ≤ Nk − 1 do
        // 4:   w[i] ← key[4 ∗ i..4 ∗ i + 3]
        // 5:   i ← i + 1
        // 6: end while ▷ When the loop concludes, i = Nk.
        for i in 0..Nk {
            key_schedule.state[i] =
                u32::from_le_bytes(key.ref_to_bytes()[i * 4..i * 4 + 4].try_into().unwrap());
        }

        key_schedule
    }

    /// This is a modified version of
    /// Algorithm 2 KeyExpansion(key)
    /// broking into a streaming mode with a low memory footprint.
    ///
    /// Also serves as the constructor and init for the [PreExpandedKeySchedule] struct.
    ///
    /// Constants (inherited from super):
    /// Nk: The number of 32-bit words comprising the key. Nk is assigned
    ///     to 4, 6, and 8 for AES-128, AES-192, and AES-256, respectively.
    ///
    /// Nr: The number of rounds. Nr is assigned to 10, 12, and 14 for
    ///     AES-128, AES-192, and AES-256, respectively.
    fn next_key(&mut self) -> Secret<[u32; Nk]> {
        // First, check that we haven't exhausted the key schedule.
        // Since this is not a pub fn, a panic here is a logic error within the library implementation,
        // so we'll only check for this in test mode.
        #[cfg(test)]
        if self.i > Nr + 1 {
            panic!("Key schedule exhausted");
        }

        // In the 0th round,
        // The first Nk words of the expanded key are the key itself, which were already loaded in
        // during init().
        if self.i == 0 {
            self.i += 1;
            return self.state.clone();
        }
        // else we're in one of the proper key rounds.
        // Every subsequent word w[i] is generated recursively from the
        // preceding word, w[i − 1], and the word Nk positions earlier, w[i − Nk], as follows:
        // 8:   temp ← w[i − 1]
        let mut temp = self.state.clone();

        // TODO Optimization note: the `i mod Nk` will trigger at fixed points in the computation.
        //      Once this is working, use Godbolt to check how this gets compiled. I hope it gets
        //      compiled unrolled and does not actually have a conditional jump here.
        //      If it's not unrolled, then we should build unrolled versions for -128, -196, -256 and
        //      see if there's a perf difference.
        // 9:   if i mod Nk = 0 then
        // 10:      temp ← SubWord(RotWord(temp)) ⊕ Rcon[i/Nk]
        if i % Nk == 0 {
            // TODO: there's probably a way to optimize either structurally or with a counter to not need the int division
            temp = SubWord(RotWord(temp)) ^ Rcon[i / Nk];
        }

        // todo finish this
        // Nk > 6 is only true for AES-256
        // 11:  else if Nk > 6 and i mod Nk = 4 then
        // 12:      temp ← SubWord(temp)
        // 13:  end if
        // 14:  w[i] ← w[i − Nk] ⊕ temp
        // 15:  i ← i + 1
        // 16: end while
    }
}
