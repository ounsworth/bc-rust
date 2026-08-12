use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{Algorithm, SecurityStrength};

use crate::key_schedule::{KeySchedule, key_expansion};
use crate::rijnael::{cipher, inv_cipher};

/* *** Parameters from FIPS 197 Table 3 (Key-Block-Round Combinations) *** */

/// The AES-128 key length in bytes; `Nk = 4` words.
pub const AES128_KEY_LEN: usize = 16;
/// The AES-192 key length in bytes; `Nk = 6` words.
pub const AES192_KEY_LEN: usize = 24;
/// The AES-256 key length in bytes; `Nk = 8` words.
pub const AES256_KEY_LEN: usize = 32;

/// The number of words in the state is denoted Nb for Rinjdael in general; in AES Nb=4.
pub(crate) const Nb: usize = 4;

/// The number of rounds `Nr` for AES-128.
pub(crate) const AES128_Nr: usize = 10;
/// The number of rounds `Nr` for AES-192.
pub(crate) const AES192_Nr: usize = 12;
/// The number of rounds `Nr` for AES-256.
pub(crate) const AES256_Nr: usize = 14;

/// The AES block length in bytes. Every AES variant has a 128-bit block (FIPS 197 Table 3).
pub const BLOCK_LEN: usize = 16;

// Dev note: once generic_const_exprs lands in rust stable, we'll be able to delete these
//           and calculate them in-place from Nr.
//
// Careful: these count the *words* in the key schedule, not the round keys. Each round key is four
//          words wide (FIPS 197 s. 5.1.4), so a schedule of 44 words holds Nr + 1 = 11 round keys.
/// The length of the AES-128 key schedule in 32-bit words: `4 * (Nr + 1) = 44` (FIPS 197 Section 5.2).
pub(crate) const AES128_Nroundkeys: usize = 4 * (AES128_Nr + 1); // 44
/// The length of the AES-192 key schedule in 32-bit words: `4 * (Nr + 1) = 52` (FIPS 197 Section 5.2).
pub(crate) const AES192_Nroundkeys: usize = 4 * (AES192_Nr + 1);
/// The length of the AES-256 key schedule in 32-bit words: `4 * (Nr + 1) = 60` (FIPS 197 Section 5.2).
pub(crate) const AES256_Nroundkeys: usize = 4 * (AES256_Nr + 1);

/* *** Key types *** */

/// The [`KeyMaterial`] type that [`AES128::new`] takes: a 128-bit AES key.
pub type AES128Key = KeyMaterial<AES128_KEY_LEN>;
/// The [`KeyMaterial`] type that [`AES192::new`] takes: a 192-bit AES key.
pub type AES192Key = KeyMaterial<AES192_KEY_LEN>;
/// The [`KeyMaterial`] type that [`AES256::new`] takes: a 256-bit AES key.
pub type AES256Key = KeyMaterial<AES256_KEY_LEN>;

/* *** The block cipher engine *** */

/// The block cipher of FIPS 197 with a 128-bit key (Table 3): `Nk = 4`, `Nr = 10`.
pub type AES128 = AES<AES128_KEY_LEN, AES128_Nr, AES128_Nroundkeys>;
/// The block cipher of FIPS 197 with a 192-bit key (Table 3): `Nk = 6`, `Nr = 12`.
pub type AES192 = AES<AES192_KEY_LEN, AES192_Nr, AES192_Nroundkeys>;
/// The block cipher of FIPS 197 with a 256-bit key (Table 3): `Nk = 8`, `Nr = 14`.
pub type AES256 = AES<AES256_KEY_LEN, AES256_Nr, AES256_Nroundkeys>;

// These three impls are what make [`AES128`], [`AES192`] and [`AES256`] the *only* usable parameter
// sets: every inherent method on `AES` is behind a `where Self: Algorithm` bound, and the orphan rule
// stops any downstream crate from adding a fourth impl of this trait for this type.
// "No other configurations of Rijndael conform to this Standard" (FIPS 197 Section 5).
impl Algorithm for AES128 {
    const ALG_NAME: &'static str = "AES-128";
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl Algorithm for AES192 {
    const ALG_NAME: &'static str = "AES-192";
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
}

impl Algorithm for AES256 {
    const ALG_NAME: &'static str = "AES-256";
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}

/// TODO: Delete scaffolding comments later
/// The AES block cipher: "a family of permutations of blocks that is parameterized by [...] the key"
/// (FIPS 197 Section 1), on one 128-bit block at a time.
///
/// Use one of the three aliases -- [`AES128`], [`AES192`] or [`AES256`] -- rather than naming this
/// type directly. [`AES::new`] expands the key once; the per-block methods then take `&self`, so one
/// engine serves as many blocks as you have.
///
/// The const parameters are the FIPS 197 Table 3 parameters, plus the schedule length that rust
/// cannot yet compute for itself:
/// * `KEY_LEN`: the key length in bytes, ie `4 * Nk`.
/// * `Nr`: the number of rounds.
/// * `Nroundkeys`: the length of the key schedule in words, `4 * (Nr + 1)`.
///
/// # 🚨 Security 🚨
///
/// This is the raw permutation. Enciphering more than one block by calling [`AES::encrypt_block`]
/// repeatedly *is* ECB mode, which leaks whenever two plaintext blocks are equal, and must not be
/// used to encrypt data. FIPS 197 is explicit that "the algorithm shall be used in conjunction with
/// a FIPS-approved or NIST-recommended mode of operation" (announcement section 8); those modes are
/// specified in the NIST SP 800-38 series and, in this crate, will be the types that implement
/// [`bouncycastle_core::traits::SymmetricCipher`] and friends.
pub struct AES<const KEY_LEN: usize, const Nr: usize, const Nroundkeys: usize> {
    /// `w`, the key schedule of FIPS 197 Section 5.2, expanded from the key by [`key_expansion`].
    /// Each word is held in a [`Secret`](bouncycastle_utils::secret::Secret), so the whole schedule
    /// is scrubbed when the engine drops. That is also why there is no `Debug` impl: there is nothing
    /// here that is safe to print.
    w: KeySchedule<Nroundkeys>,
}

impl<const KEY_LEN: usize, const Nr: usize, const Nroundkeys: usize> AES<KEY_LEN, Nr, Nroundkeys>
where
    Self: Algorithm,
{
    /// A compile-time check that this instantiation is one of the three parameter sets of FIPS 197
    /// Table 3, and that the three parameters are consistent with each other.
    ///
    /// The `Self: Algorithm` bound above already limits callers to the three aliases; this is a
    /// second, independent guard that catches a typo *inside this crate* -- declaring [`AES192`] with
    /// a 50-word schedule, say -- at compile time instead of as a wrong answer at run time.
    const VALID_PARAMS: () = {
        assert!(
            KEY_LEN == AES128_KEY_LEN || KEY_LEN == AES192_KEY_LEN || KEY_LEN == AES256_KEY_LEN,
            "AES key length must be 16, 24 or 32 bytes (FIPS 197 Table 3)"
        );
        // Table 3: Nr = Nk + 6, where Nk = KEY_LEN / 4.
        assert!(Nr == KEY_LEN / 4 + 6, "AES round count must be Nk + 6 (FIPS 197 Table 3)");
        // Section 5.2: the key schedule holds 4 * (Nr + 1) words.
        assert!(
            Nroundkeys == 4 * (Nr + 1),
            "AES key schedule must hold 4 * (Nr + 1) words (FIPS 197 Section 5.2)"
        );
    };

    /// Creates an engine from a cipher key by running KeyExpansion() (FIPS 197 Algorithm 2).
    ///
    /// Expanding the key is the only expensive part of AES, so build one engine and reuse it.
    ///
    /// The key must be exactly `KEY_LEN` bytes of [`KeyType::SymmetricCipherKey`] or
    /// [`KeyType::CryptographicRandom`], tagged at a [`SecurityStrength`] of at least this variant's
    /// strength. This is the only place in the crate that can fail: with the key validated here, and
    /// the block length fixed by the type system, the per-block methods below cannot.
    ///
    /// # Errors
    ///
    /// * [`KeyMaterialError::InvalidKeyType`] if the key is not tagged as a symmetric cipher key or
    ///   as full-entropy random. Note that an all-zero buffer arrives tagged
    ///   [`KeyType::Zeroized`] and is refused here.
    /// * [`KeyMaterialError::InvalidLength`] if the key holds fewer than `KEY_LEN` bytes. (It cannot
    ///   hold more; the capacity is `KEY_LEN`.)
    /// * [`KeyMaterialError::SecurityStrength`] if the key is tagged weaker than the variant needs --
    ///   a 128-bit-strength key handed to [`AES256`], for example.
    pub fn new(key: &KeyMaterial<KEY_LEN>) -> Result<Self, SymmetricCipherError> {
        // Force the compile-time parameter check for this instantiation. Free at run time.
        let () = Self::VALID_PARAMS;

        // Wrong kind of key: refuse to use, say, a MAC key or an unclassified buffer as a cipher key.
        // Keeping keys separate between algorithms is a security property, not a formality.
        if !(key.key_type() == KeyType::SymmetricCipherKey
            || key.key_type() == KeyType::CryptographicRandom)
        {
            return Err(KeyMaterialError::InvalidKeyType(
                "AES::new(): key must be a SymmetricCipherKey or CryptographicRandom KeyType",
            )
            .into());
        }

        // A short key would otherwise be silently zero-padded by KeyExpansion(); this check is also
        // what makes the `try_into()` on the key bytes in `key_expansion()` infallible.
        if key.key_len() != KEY_LEN {
            return Err(KeyMaterialError::InvalidLength.into());
        }

        // A key tagged weaker than the algorithm does not actually deliver the security level the
        // caller thinks this variant is giving them.
        if key.security_strength() < Self::MAX_SECURITY_STRENGTH {
            return Err(KeyMaterialError::SecurityStrength(
                "AES::new(): key security strength is lower than the AES variant requires",
            )
            .into());
        }

        Ok(Self { w: key_expansion::<KEY_LEN, Nroundkeys>(key) })
    }

    /// Cipher(): enciphers one block in place (FIPS 197 Algorithm 1).
    ///
    /// In-place rather than returning a new block, which is the convention everywhere in this crate:
    /// a mode of operation walking a buffer wants it this way, and it keeps one fewer copy of the
    /// data in memory.
    ///
    /// # 🚨 Security 🚨
    ///
    /// Calling this on block after block is ECB mode. See the type-level docs.
    pub fn encrypt_block(&self, block: &mut [u8; BLOCK_LEN]) {
        cipher::<Nr, Nroundkeys>(block, &self.w);
    }

    /// InvCipher(): deciphers one block in place (FIPS 197 Algorithm 3); the exact inverse of
    /// [`AES::encrypt_block`].
    pub fn decrypt_block(&self, block: &mut [u8; BLOCK_LEN]) {
        inv_cipher::<Nr, Nroundkeys>(block, &self.w);
    }

    /// One-shot: expands `key` and enciphers exactly one block in place with it.
    ///
    /// Convenient for a single block, but it runs the full key expansion on every call. For more
    /// than one block, build an engine with [`AES::new`] and call [`AES::encrypt_block`] repeatedly.
    /// The engine -- and with it the key schedule -- is scrubbed before this returns.
    ///
    /// # Errors
    ///
    /// As [`AES::new`].
    pub fn encrypt_single_block(
        key: &KeyMaterial<KEY_LEN>,
        block: &mut [u8; BLOCK_LEN],
    ) -> Result<(), SymmetricCipherError> {
        Self::new(key)?.encrypt_block(block);
        Ok(())
    }

    /// One-shot: expands `key` and deciphers exactly one block in place with it.
    ///
    /// # Errors
    ///
    /// As [`AES::new`].
    pub fn decrypt_single_block(
        key: &KeyMaterial<KEY_LEN>,
        block: &mut [u8; BLOCK_LEN],
    ) -> Result<(), SymmetricCipherError> {
        Self::new(key)?.decrypt_block(block);
        Ok(())
    }
}

/* *** TODO: Modes *** */

/* *** AES_CBC *** */
// Defined in SP 800-38a section 6.2
// TODO -- there are other modes defined in SP 800-38a, but I don't think they ever really got used.

pub type AES128_CBC = AES_CBC<AES128_KEY_LEN, AES128_Nr>;
pub type AES192_CBC = AES_CBC<AES192_KEY_LEN, AES192_Nr>;
pub type AES256_CBC = AES_CBC<AES256_KEY_LEN, AES256_Nr>;

pub struct AES_CBC<const KEY_LEN: usize, const Nr: usize> {
    // TODO
}

// impl BlockCipher<> for AES_CBC {
//     // TODO
// }

/* *** AES_GCM *** */

pub type AES128_GCM = AES_GCM<AES128_KEY_LEN, AES128_Nr>;
pub type AES192_GCM = AES_GCM<AES192_KEY_LEN, AES192_Nr>;
pub type AES256_GCM = AES_GCM<AES256_KEY_LEN, AES256_Nr>;

pub struct AES_GCM<const KEY_LEN: usize, const Nr: usize> {
    // TODO
}

// impl AEADCipher<> for AES_GCM {
//     // TODO
// }

// TODO --  Other modes we could implement:
//          * Key Wrap (KW and KWP from SP 800-38F)
//          * CMAC (SP 800-38B / RFC4493)
//          * GMAC (SP 800-38D / RFC9044)
//          * AES_CTR (SP 800-38A), it's sortof a bad stream cipher, but it's possible that it's
//            used in some protocol that could make it worthwhile to implement in bc-rust.
//          * AES_CCM (RFC4309 / NIST SP 800-38C), it's sortof an early version of what
//            we now call an AEAD and its use was largely replaced by AES_GCM once that was invented.
//            it's possible that it's used in some protocol that could make it worthwhile to implement in bc-rust.
