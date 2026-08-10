use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait};
use bouncycastle_utils::secret::Secret;

use crate::rijnael::*;
use crate::sbox::sub_word;

/// A round key is defined in FIPS 197 s. 5.1.4 as four words (ie four bytes), which is represented here as a u32.
/// This is the same for all AES sizes.
/// A type alias is defined to disambiguate round keys from other u32 data types.
pub(crate) type RoundKey = Secret<u32>;

/// The AES key schedule is expanded from the main key.
/// It consists of Nr round keys each of which is a 4-byte word (represented here as a [`RoundKey`],
/// which is simply a type alias for a u32.
///
/// The size in memory of the KeySchedule is:
/// * AES-128: Nr=10, Nroundkeys = 4*(Nr + 1) = 44 words = 176 bytes.
/// * AES-192: Nr=12, Nroundkeys = 4*(Nr + 1) = 52 words = 208 bytes.
/// * AES-256: Nr=14, Nroundkeys = 4*(Nr + 1) = 60 words = 240 bytes.
// Dev Note: ugg, this would be so easy if generic_const_exprs was on rust main,
//           cause then we'd size this as `KeySchedule<const Nr: usize> = [RoundKey; 4*(Nr + 1)];`
//           instead of having to carry another param.
pub(crate) type KeySchedule<const Nroundkeys: usize> = [RoundKey; Nroundkeys];

/// Algorithm 2 KeyExpansion(key)
///
/// Also serves as the constructor and init for the [KeySchedule] struct.
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
fn key_expansion<const KEY_LEN: usize, const Nroundkeys: usize>(
    key: &KeyMaterial<KEY_LEN>,
) -> KeySchedule<Nroundkeys> {
    // todo -- do KeyType and SecurityStrength checks on key. That'll mean returning a Result

    let mut w: KeySchedule<Nroundkeys> = [const { RoundKey::new() }; Nroundkeys];

    // The number of u32 words in the AES key.
    // AES-128 Nk: 4
    // AES-192 Nk: 6
    // AES-256 Nk: 8
    #[allow(non_snake_case)]
    let Nk: usize = KEY_LEN / 4;

    // The first Nk words of the expanded key are the key itself.
    // 2: i ← 0
    // 3: while i ≤ Nk − 1 do
    // 4:   w[i] ← key[4 ∗ i..4 ∗ i + 3]
    // 5:   i ← i + 1
    // 6: end while ▷ When the loop concludes, i = Nk.
    for i in 0..Nk {
        *w[i] = u32::from_be_bytes(key.ref_to_bytes()[i * 4..i * 4 + 4].try_into().unwrap());
    }

    // Every subsequent word w[i] is generated recursively from the
    // preceding word, w[i − 1], and the word Nk positions earlier, w[i − Nk], as follows:
    // 7: while i ≤ 4 ∗ Nr + 3 do
    //  Nroundkeys = 4 * (Nr + 1), computed as a global constant
    for i in Nk..Nroundkeys {
        // 8: temp ← w[i − 1]
        let mut temp = w[i - 1].clone();

        // TODO --  these % and / operations don't matter for constant-time since they are acting
        //          on the loop counter, which is not a secret.
        //          But we could do some science and see if perf improves by replacing
        //          them both with counters.

        // 9: if i mod Nk = 0 then
        if i % Nk == 0 {
            // 10: temp ← SubWord(RotWord(temp)) ⊕ Rcon[i/Nk]
            //    Deviation from the FIPS: we're indexing Rcon from 0 whereas FIPS 197 indexes from 1.
            *temp = sub_word(rot_word(*temp)) ^ Rcon[(i / Nk) - 1];
        }
        // 11: else if Nk > 6 and i mod Nk = 4 then
        //      ▷ Nk > 6 is only true for AES-256
        else if Nk > 6 && i % Nk == 4 {
            // 12: temp ← SubWord(temp)
            *temp = sub_word(*temp);
        } // 13: end if

        // 14:  w[i] ← w[i − Nk] ⊕ temp
        *w[i] = *w[i - Nk] ^ *temp;

        // 15: i ← i + 1
        //  Handled by for loop
    } // 16: end while

    // 17: return w
    w
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
const Rcon: [u32; 10] = [
    u32::from_be_bytes([0x01, 0x00, 0x00, 0x00]),
    u32::from_be_bytes([0x02, 0x00, 0x00, 0x00]),
    u32::from_be_bytes([0x04, 0x00, 0x00, 0x00]),
    u32::from_be_bytes([0x08, 0x00, 0x00, 0x00]),
    u32::from_be_bytes([0x10, 0x00, 0x00, 0x00]),
    u32::from_be_bytes([0x20, 0x00, 0x00, 0x00]),
    u32::from_be_bytes([0x40, 0x00, 0x00, 0x00]),
    u32::from_be_bytes([0x80, 0x00, 0x00, 0x00]),
    u32::from_be_bytes([0x1b, 0x00, 0x00, 0x00]),
    u32::from_be_bytes([0x36, 0x00, 0x00, 0x00]),
];

#[cfg(test)]
mod key_schedule_tests {
    use super::*;
    use crate::aes::{AES128_KEY_LEN, AES192_KEY_LEN, AES256_KEY_LEN};
    use crate::aes::{AES128_Nr, AES192_Nr, AES256_Nr};
    use crate::aes::{AES128_Nroundkeys, AES192_Nroundkeys, AES256_Nroundkeys};
    use bouncycastle_core::key_material::{
        KeyMaterial128, KeyMaterial192, KeyMaterial256, KeyType,
    };

    /// FIPS 197 Appendix A.1
    /// contains a worked example of expanding the key schedule for a 128-bit key
    #[test]
    fn appdx_a1() {
        let key = KeyMaterial128::from_bytes_as_type(
            b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
            KeyType::SymmetricCipherKey,
        )
        .unwrap();

        // check the constants
        assert_eq!(AES128_KEY_LEN, 16);
        assert_eq!(AES128_Nr, 10);
        assert_eq!(AES128_Nroundkeys, 44);

        // The expected values are the `w[i] = temp ⊕ w[i−Nk]` column of the Appendix A.1 table
        // (words 0..3 are the key itself, listed above that table as w_0 .. w_3).
        let w: [u32; 44] = [
            u32::from_be_bytes([0x2b, 0x7e, 0x15, 0x16]), // w[0]
            u32::from_be_bytes([0x28, 0xae, 0xd2, 0xa6]), // w[1]
            u32::from_be_bytes([0xab, 0xf7, 0x15, 0x88]), // w[2]
            u32::from_be_bytes([0x09, 0xcf, 0x4f, 0x3c]), // w[3]
            u32::from_be_bytes([0xa0, 0xfa, 0xfe, 0x17]), // w[4]
            u32::from_be_bytes([0x88, 0x54, 0x2c, 0xb1]), // w[5]
            u32::from_be_bytes([0x23, 0xa3, 0x39, 0x39]), // w[6]
            u32::from_be_bytes([0x2a, 0x6c, 0x76, 0x05]), // w[7]
            u32::from_be_bytes([0xf2, 0xc2, 0x95, 0xf2]), // w[8]
            u32::from_be_bytes([0x7a, 0x96, 0xb9, 0x43]), // w[9]
            u32::from_be_bytes([0x59, 0x35, 0x80, 0x7a]), // w[10]
            u32::from_be_bytes([0x73, 0x59, 0xf6, 0x7f]), // w[11]
            u32::from_be_bytes([0x3d, 0x80, 0x47, 0x7d]), // w[12]
            u32::from_be_bytes([0x47, 0x16, 0xfe, 0x3e]), // w[13]
            u32::from_be_bytes([0x1e, 0x23, 0x7e, 0x44]), // w[14]
            u32::from_be_bytes([0x6d, 0x7a, 0x88, 0x3b]), // w[15]
            u32::from_be_bytes([0xef, 0x44, 0xa5, 0x41]), // w[16]
            u32::from_be_bytes([0xa8, 0x52, 0x5b, 0x7f]), // w[17]
            u32::from_be_bytes([0xb6, 0x71, 0x25, 0x3b]), // w[18]
            u32::from_be_bytes([0xdb, 0x0b, 0xad, 0x00]), // w[19]
            u32::from_be_bytes([0xd4, 0xd1, 0xc6, 0xf8]), // w[20]
            u32::from_be_bytes([0x7c, 0x83, 0x9d, 0x87]), // w[21]
            u32::from_be_bytes([0xca, 0xf2, 0xb8, 0xbc]), // w[22]
            u32::from_be_bytes([0x11, 0xf9, 0x15, 0xbc]), // w[23]
            u32::from_be_bytes([0x6d, 0x88, 0xa3, 0x7a]), // w[24]
            u32::from_be_bytes([0x11, 0x0b, 0x3e, 0xfd]), // w[25]
            u32::from_be_bytes([0xdb, 0xf9, 0x86, 0x41]), // w[26]
            u32::from_be_bytes([0xca, 0x00, 0x93, 0xfd]), // w[27]
            u32::from_be_bytes([0x4e, 0x54, 0xf7, 0x0e]), // w[28]
            u32::from_be_bytes([0x5f, 0x5f, 0xc9, 0xf3]), // w[29]
            u32::from_be_bytes([0x84, 0xa6, 0x4f, 0xb2]), // w[30]
            u32::from_be_bytes([0x4e, 0xa6, 0xdc, 0x4f]), // w[31]
            u32::from_be_bytes([0xea, 0xd2, 0x73, 0x21]), // w[32]
            u32::from_be_bytes([0xb5, 0x8d, 0xba, 0xd2]), // w[33]
            u32::from_be_bytes([0x31, 0x2b, 0xf5, 0x60]), // w[34]
            u32::from_be_bytes([0x7f, 0x8d, 0x29, 0x2f]), // w[35]
            u32::from_be_bytes([0xac, 0x77, 0x66, 0xf3]), // w[36]
            u32::from_be_bytes([0x19, 0xfa, 0xdc, 0x21]), // w[37]
            u32::from_be_bytes([0x28, 0xd1, 0x29, 0x41]), // w[38]
            u32::from_be_bytes([0x57, 0x5c, 0x00, 0x6e]), // w[39]
            u32::from_be_bytes([0xd0, 0x14, 0xf9, 0xa8]), // w[40]
            u32::from_be_bytes([0xc9, 0xee, 0x25, 0x89]), // w[41]
            u32::from_be_bytes([0xe1, 0x3f, 0x0c, 0xc8]), // w[42]
            u32::from_be_bytes([0xb6, 0x63, 0x0c, 0xa6]), // w[43]
        ];

        let key_schedule = key_expansion::<AES128_KEY_LEN, AES128_Nroundkeys>(&key);

        for i in 0..AES128_Nroundkeys {
            assert_eq!(w[i], *key_schedule[i], "i={}", i);
        }
    }

    /// FIPS 197 Appendix A.2
    /// contains a worked example of expanding the key schedule for a 196-bit key
    #[test]
    fn appdx_a2() {
        let key = KeyMaterial192::from_bytes_as_type(
            b"\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5\x62\xf8\xea\xd2\x52\x2c\x6b\x7b",
            KeyType::SymmetricCipherKey,
        ).unwrap();

        // check the constants
        assert_eq!(AES192_KEY_LEN, 24);
        assert_eq!(AES192_Nr, 12);
        assert_eq!(AES192_Nroundkeys, 52);

        // The expected values are the `w[i] = temp ⊕ w[i−Nk]` column of the Appendix A.2 table
        // (words 0..5 are the key itself, listed above that table as w_0 .. w_5).
        let w: [u32; 52] = [
            u32::from_be_bytes([0x8e, 0x73, 0xb0, 0xf7]), // w[0]
            u32::from_be_bytes([0xda, 0x0e, 0x64, 0x52]), // w[1]
            u32::from_be_bytes([0xc8, 0x10, 0xf3, 0x2b]), // w[2]
            u32::from_be_bytes([0x80, 0x90, 0x79, 0xe5]), // w[3]
            u32::from_be_bytes([0x62, 0xf8, 0xea, 0xd2]), // w[4]
            u32::from_be_bytes([0x52, 0x2c, 0x6b, 0x7b]), // w[5]
            u32::from_be_bytes([0xfe, 0x0c, 0x91, 0xf7]), // w[6]
            u32::from_be_bytes([0x24, 0x02, 0xf5, 0xa5]), // w[7]
            u32::from_be_bytes([0xec, 0x12, 0x06, 0x8e]), // w[8]
            u32::from_be_bytes([0x6c, 0x82, 0x7f, 0x6b]), // w[9]
            u32::from_be_bytes([0x0e, 0x7a, 0x95, 0xb9]), // w[10]
            u32::from_be_bytes([0x5c, 0x56, 0xfe, 0xc2]), // w[11]
            u32::from_be_bytes([0x4d, 0xb7, 0xb4, 0xbd]), // w[12]
            u32::from_be_bytes([0x69, 0xb5, 0x41, 0x18]), // w[13]
            u32::from_be_bytes([0x85, 0xa7, 0x47, 0x96]), // w[14]
            u32::from_be_bytes([0xe9, 0x25, 0x38, 0xfd]), // w[15]
            u32::from_be_bytes([0xe7, 0x5f, 0xad, 0x44]), // w[16]
            u32::from_be_bytes([0xbb, 0x09, 0x53, 0x86]), // w[17]
            u32::from_be_bytes([0x48, 0x5a, 0xf0, 0x57]), // w[18]
            u32::from_be_bytes([0x21, 0xef, 0xb1, 0x4f]), // w[19]
            u32::from_be_bytes([0xa4, 0x48, 0xf6, 0xd9]), // w[20]
            u32::from_be_bytes([0x4d, 0x6d, 0xce, 0x24]), // w[21]
            u32::from_be_bytes([0xaa, 0x32, 0x63, 0x60]), // w[22]
            u32::from_be_bytes([0x11, 0x3b, 0x30, 0xe6]), // w[23]
            u32::from_be_bytes([0xa2, 0x5e, 0x7e, 0xd5]), // w[24]
            u32::from_be_bytes([0x83, 0xb1, 0xcf, 0x9a]), // w[25]
            u32::from_be_bytes([0x27, 0xf9, 0x39, 0x43]), // w[26]
            u32::from_be_bytes([0x6a, 0x94, 0xf7, 0x67]), // w[27]
            u32::from_be_bytes([0xc0, 0xa6, 0x94, 0x07]), // w[28]
            u32::from_be_bytes([0xd1, 0x9d, 0xa4, 0xe1]), // w[29]
            u32::from_be_bytes([0xec, 0x17, 0x86, 0xeb]), // w[30]
            u32::from_be_bytes([0x6f, 0xa6, 0x49, 0x71]), // w[31]
            u32::from_be_bytes([0x48, 0x5f, 0x70, 0x32]), // w[32]
            u32::from_be_bytes([0x22, 0xcb, 0x87, 0x55]), // w[33]
            u32::from_be_bytes([0xe2, 0x6d, 0x13, 0x52]), // w[34]
            u32::from_be_bytes([0x33, 0xf0, 0xb7, 0xb3]), // w[35]
            u32::from_be_bytes([0x40, 0xbe, 0xeb, 0x28]), // w[36]
            u32::from_be_bytes([0x2f, 0x18, 0xa2, 0x59]), // w[37]
            u32::from_be_bytes([0x67, 0x47, 0xd2, 0x6b]), // w[38]
            u32::from_be_bytes([0x45, 0x8c, 0x55, 0x3e]), // w[39]
            u32::from_be_bytes([0xa7, 0xe1, 0x46, 0x6c]), // w[40]
            u32::from_be_bytes([0x94, 0x11, 0xf1, 0xdf]), // w[41]
            u32::from_be_bytes([0x82, 0x1f, 0x75, 0x0a]), // w[42]
            u32::from_be_bytes([0xad, 0x07, 0xd7, 0x53]), // w[43]
            u32::from_be_bytes([0xca, 0x40, 0x05, 0x38]), // w[44]
            u32::from_be_bytes([0x8f, 0xcc, 0x50, 0x06]), // w[45]
            u32::from_be_bytes([0x28, 0x2d, 0x16, 0x6a]), // w[46]
            u32::from_be_bytes([0xbc, 0x3c, 0xe7, 0xb5]), // w[47]
            u32::from_be_bytes([0xe9, 0x8b, 0xa0, 0x6f]), // w[48]
            u32::from_be_bytes([0x44, 0x8c, 0x77, 0x3c]), // w[49]
            u32::from_be_bytes([0x8e, 0xcc, 0x72, 0x04]), // w[50]
            u32::from_be_bytes([0x01, 0x00, 0x22, 0x02]), // w[51]
        ];

        let key_schedule = key_expansion::<AES192_KEY_LEN, AES192_Nroundkeys>(&key);

        for i in 0..AES192_Nroundkeys {
            assert_eq!(w[i], *key_schedule[i]);
        }
    }

    /// FIPS 197 Appendix A.3
    /// contains a worked example of expanding the key schedule for a 256-bit key
    #[test]
    fn appdx_a3() {
        let key = KeyMaterial256::from_bytes_as_type(
            b"\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4",
            KeyType::SymmetricCipherKey,
        ).unwrap();

        // check the constants
        assert_eq!(AES256_KEY_LEN, 32);
        assert_eq!(AES256_Nr, 14);
        assert_eq!(AES256_Nroundkeys, 60);

        // The expected values are the `w[i] = temp ⊕ w[i−Nk]` column of the Appendix A.3 table
        // (words 0..7 are the key itself, listed above that table as w_0 .. w_7).
        let w: [u32; 60] = [
            u32::from_be_bytes([0x60, 0x3d, 0xeb, 0x10]), // w[0]
            u32::from_be_bytes([0x15, 0xca, 0x71, 0xbe]), // w[1]
            u32::from_be_bytes([0x2b, 0x73, 0xae, 0xf0]), // w[2]
            u32::from_be_bytes([0x85, 0x7d, 0x77, 0x81]), // w[3]
            u32::from_be_bytes([0x1f, 0x35, 0x2c, 0x07]), // w[4]
            u32::from_be_bytes([0x3b, 0x61, 0x08, 0xd7]), // w[5]
            u32::from_be_bytes([0x2d, 0x98, 0x10, 0xa3]), // w[6]
            u32::from_be_bytes([0x09, 0x14, 0xdf, 0xf4]), // w[7]
            u32::from_be_bytes([0x9b, 0xa3, 0x54, 0x11]), // w[8]
            u32::from_be_bytes([0x8e, 0x69, 0x25, 0xaf]), // w[9]
            u32::from_be_bytes([0xa5, 0x1a, 0x8b, 0x5f]), // w[10]
            u32::from_be_bytes([0x20, 0x67, 0xfc, 0xde]), // w[11]
            u32::from_be_bytes([0xa8, 0xb0, 0x9c, 0x1a]), // w[12]
            u32::from_be_bytes([0x93, 0xd1, 0x94, 0xcd]), // w[13]
            u32::from_be_bytes([0xbe, 0x49, 0x84, 0x6e]), // w[14]
            u32::from_be_bytes([0xb7, 0x5d, 0x5b, 0x9a]), // w[15]
            u32::from_be_bytes([0xd5, 0x9a, 0xec, 0xb8]), // w[16]
            u32::from_be_bytes([0x5b, 0xf3, 0xc9, 0x17]), // w[17]
            u32::from_be_bytes([0xfe, 0xe9, 0x42, 0x48]), // w[18]
            u32::from_be_bytes([0xde, 0x8e, 0xbe, 0x96]), // w[19]
            u32::from_be_bytes([0xb5, 0xa9, 0x32, 0x8a]), // w[20]
            u32::from_be_bytes([0x26, 0x78, 0xa6, 0x47]), // w[21]
            u32::from_be_bytes([0x98, 0x31, 0x22, 0x29]), // w[22]
            u32::from_be_bytes([0x2f, 0x6c, 0x79, 0xb3]), // w[23]
            u32::from_be_bytes([0x81, 0x2c, 0x81, 0xad]), // w[24]
            u32::from_be_bytes([0xda, 0xdf, 0x48, 0xba]), // w[25]
            u32::from_be_bytes([0x24, 0x36, 0x0a, 0xf2]), // w[26]
            u32::from_be_bytes([0xfa, 0xb8, 0xb4, 0x64]), // w[27]
            u32::from_be_bytes([0x98, 0xc5, 0xbf, 0xc9]), // w[28]
            u32::from_be_bytes([0xbe, 0xbd, 0x19, 0x8e]), // w[29]
            u32::from_be_bytes([0x26, 0x8c, 0x3b, 0xa7]), // w[30]
            u32::from_be_bytes([0x09, 0xe0, 0x42, 0x14]), // w[31]
            u32::from_be_bytes([0x68, 0x00, 0x7b, 0xac]), // w[32]
            u32::from_be_bytes([0xb2, 0xdf, 0x33, 0x16]), // w[33]
            u32::from_be_bytes([0x96, 0xe9, 0x39, 0xe4]), // w[34]
            u32::from_be_bytes([0x6c, 0x51, 0x8d, 0x80]), // w[35]
            u32::from_be_bytes([0xc8, 0x14, 0xe2, 0x04]), // w[36]
            u32::from_be_bytes([0x76, 0xa9, 0xfb, 0x8a]), // w[37]
            u32::from_be_bytes([0x50, 0x25, 0xc0, 0x2d]), // w[38]
            u32::from_be_bytes([0x59, 0xc5, 0x82, 0x39]), // w[39]
            u32::from_be_bytes([0xde, 0x13, 0x69, 0x67]), // w[40]
            u32::from_be_bytes([0x6c, 0xcc, 0x5a, 0x71]), // w[41]
            u32::from_be_bytes([0xfa, 0x25, 0x63, 0x95]), // w[42]
            u32::from_be_bytes([0x96, 0x74, 0xee, 0x15]), // w[43]
            u32::from_be_bytes([0x58, 0x86, 0xca, 0x5d]), // w[44]
            u32::from_be_bytes([0x2e, 0x2f, 0x31, 0xd7]), // w[45]
            u32::from_be_bytes([0x7e, 0x0a, 0xf1, 0xfa]), // w[46]
            u32::from_be_bytes([0x27, 0xcf, 0x73, 0xc3]), // w[47]
            u32::from_be_bytes([0x74, 0x9c, 0x47, 0xab]), // w[48]
            u32::from_be_bytes([0x18, 0x50, 0x1d, 0xda]), // w[49]
            u32::from_be_bytes([0xe2, 0x75, 0x7e, 0x4f]), // w[50]
            u32::from_be_bytes([0x74, 0x01, 0x90, 0x5a]), // w[51]
            u32::from_be_bytes([0xca, 0xfa, 0xaa, 0xe3]), // w[52]
            u32::from_be_bytes([0xe4, 0xd5, 0x9b, 0x34]), // w[53]
            u32::from_be_bytes([0x9a, 0xdf, 0x6a, 0xce]), // w[54]
            u32::from_be_bytes([0xbd, 0x10, 0x19, 0x0d]), // w[55]
            u32::from_be_bytes([0xfe, 0x48, 0x90, 0xd1]), // w[56]
            u32::from_be_bytes([0xe6, 0x18, 0x8d, 0x0b]), // w[57]
            u32::from_be_bytes([0x04, 0x6d, 0xf3, 0x44]), // w[58]
            u32::from_be_bytes([0x70, 0x6c, 0x63, 0x1e]), // w[59]
        ];

        let key_schedule = key_expansion::<AES256_KEY_LEN, AES256_Nroundkeys>(&key);

        for i in 0..AES256_Nroundkeys {
            assert_eq!(w[i], *key_schedule[i]);
        }
    }
}
