//! Test the AES block cipher against the bc-test-data repo, expected at "../bc-test-data" relative
//! to the root of this git project. If it is not there, the tests print a warning and pass.
//!
//! Exercises `crypto/aes_tdes_vectors/AES/ACVP-AES-ECB.*.{rsp,res}.json`. An ACVP-AES-ECB AFT vector
//! is a known-answer test for the raw FIPS 197 permutation: one key, one block in, one block out.
//! This crate does not implement ECB -- the harness drives the permutation once per block.
//!
//! ACVP files are named `<algorithm>.<sessionId>.<kind>.json`: `.req` holds the prompts, `.rsp` the
//! answers, `.res` NIST's verdict on the session. The session id changes whenever the vectors are
//! regenerated, so files are located by prefix.

use bouncycastle_aes::{
    AES128, AES128_KEY_LEN, AES192, AES192_KEY_LEN, AES256, AES256_KEY_LEN, BLOCK_LEN,
};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::SecurityStrength;

#[cfg(test)]
mod bc_test_data {
    use super::*;
    use bouncycastle_core::key_material::do_hazardous_operations;
    use bouncycastle_hex as hex;
    use std::fs;
    use std::path::Path;
    use std::sync::Once;

    const TEST_DATA_PATH_RELATIVE: &str = "../../../bc-test-data/crypto/aes_tdes_vectors";
    const TEST_DATA_PATH: &str = "../bc-test-data/crypto/aes_tdes_vectors";

    static TEST_DATA_CHECK: Once = Once::new();

    /// The two candidates cover running from the crate directory and from the workspace root.
    fn test_data_dir() -> Option<&'static str> {
        let dir = if Path::new(TEST_DATA_PATH_RELATIVE).exists() {
            Some(TEST_DATA_PATH_RELATIVE)
        } else if Path::new(TEST_DATA_PATH).exists() {
            Some(TEST_DATA_PATH)
        } else {
            None
        };

        // just print once
        TEST_DATA_CHECK.call_once(|| match dir {
            Some(found) => println!("bc-test-data found at: {found:?}"),
            None => println!("WARNING: bc-test-data directory not found; tests will be skipped"),
        });

        dir
    }

    /// Reads the one file in `subdir` named `<prefix>.<sessionId>.<kind>.json`. Matching on
    /// `<prefix>.` keeps `ACVP-AES-CBC` from also picking up `ACVP-AES-CBC-CS1` and friends.
    fn get_test_data(subdir: &str, prefix: &str, kind: &str) -> Result<String, ()> {
        let base = test_data_dir().ok_or(())?;
        let dir = format!("{base}/{subdir}");
        let prefix = format!("{prefix}.");
        let suffix = format!(".{kind}.json");

        for entry in fs::read_dir(&dir).map_err(|_| ())?.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with(&prefix) && name.ends_with(&suffix) {
                return fs::read_to_string(entry.path()).map_err(|_| ());
            }
        }

        println!("WARNING: no {prefix}*{suffix} in {dir}; test skipped");
        Err(())
    }

    /// The ACVP sets include all-zero keys, which arrive tagged [`KeyType::Zeroized`] with no
    /// security strength and are rightly refused by `AES::new()`. Promote them back.
    fn key_material_from<const KEY_LEN: usize>(
        bytes: &[u8],
        strength: SecurityStrength,
    ) -> KeyMaterial<KEY_LEN> {
        let mut key =
            KeyMaterial::<KEY_LEN>::from_bytes_as_type(bytes, KeyType::SymmetricCipherKey)
                .expect("ACVP key is not a valid length for this variant");

        if key.key_type() != KeyType::SymmetricCipherKey {
            do_hazardous_operations(&mut key, |key| {
                key.set_key_type(KeyType::SymmetricCipherKey)?;
                key.set_security_strength(strength)?;
                Ok(())
            })
            .expect("could not promote an all-zero ACVP key");
        }

        key
    }

    /* *** ACVP-AES-ECB *** */

    /// An AFT response carries the whole `(key, pt, ct)` triple, and `ct = CIPHER(key, pt)` holds
    /// whichever direction the prompt asked for, so `direction` is not needed and every case is run
    /// both ways.
    #[derive(Clone)]
    struct EcbTestCase {
        tg_id: u64,
        tc_id: u64,
        key: Vec<u8>,
        pt: Vec<u8>,
        ct: Vec<u8>,
    }

    impl EcbTestCase {
        /// Returns the AFT cases, and the number of non-AFT cases skipped.
        fn parse(data: String) -> (Vec<Self>, usize) {
            let json: serde_json::Value =
                serde_json::from_str(&data).expect("test data is not valid JSON");

            let mut test_cases = Vec::<Self>::new();
            let mut skipped = 0_usize;

            // An ACVP file is [ {acvVersion}, {vsId, testGroups: [...]} ].
            let groups = json[1]["testGroups"].as_array().expect("testGroups is not an array");
            for group in groups {
                let tg_id = group["tgId"].as_u64().expect("tgId missing");
                let tests = group["tests"].as_array().expect("tests is not an array");

                for test in tests {
                    let tc_id = test["tcId"].as_u64().expect("tcId missing");

                    // TODO --  A Monte Carlo (MCT) case answers with a 100-entry `resultsArray`
                    //          rather than a single value, and needs the ACVP key-mangling chain to
                    //          check. Skipped and counted for now.
                    match (test["key"].as_str(), test["pt"].as_str(), test["ct"].as_str()) {
                        (Some(key), Some(pt), Some(ct)) => test_cases.push(Self {
                            tg_id,
                            tc_id,
                            key: hex::decode(key).expect("key is not valid hex"),
                            pt: hex::decode(pt).expect("pt is not valid hex"),
                            ct: hex::decode(ct).expect("ct is not valid hex"),
                        }),
                        _ => skipped += 1,
                    }
                }
            }

            (test_cases, skipped)
        }

        /// Runs both directions against the variant the key length selects; returns blocks checked.
        fn run(&self) -> usize {
            assert_eq!(
                self.pt.len(),
                self.ct.len(),
                "tcId {}: pt and ct are different lengths",
                self.tc_id
            );
            assert_eq!(
                self.pt.len() % BLOCK_LEN,
                0,
                "tcId {}: payload is not a whole number of blocks",
                self.tc_id
            );
            assert_ne!(self.pt.len(), 0, "tcId {}: empty payload", self.tc_id);

            // A macro because the three engines are distinct types.
            macro_rules! check {
                ($engine:ty, $key_len:expr, $strength:expr) => {{
                    let key = key_material_from::<$key_len>(&self.key, $strength);
                    let engine = <$engine>::new(&key).expect("AES::new() rejected an ACVP key");

                    // 54 of these payloads run from 2 to 10 blocks, each enciphered independently
                    // under the same key.
                    for (i, (pt, ct)) in self
                        .pt
                        .chunks_exact(BLOCK_LEN)
                        .zip(self.ct.chunks_exact(BLOCK_LEN))
                        .enumerate()
                    {
                        // The length checks above make this conversion infallible.
                        let mut block: [u8; BLOCK_LEN] = pt.try_into().unwrap();

                        engine.encrypt_block(&mut block);
                        assert_eq!(
                            &block[..],
                            ct,
                            "encrypt: tgId {} tcId {} block {i} ({}-bit key)",
                            self.tg_id,
                            self.tc_id,
                            self.key.len() * 8
                        );

                        engine.decrypt_block(&mut block);
                        assert_eq!(
                            &block[..],
                            pt,
                            "decrypt: tgId {} tcId {} block {i} ({}-bit key)",
                            self.tg_id,
                            self.tc_id,
                            self.key.len() * 8
                        );
                    }
                }};
            }

            match self.key.len() {
                AES128_KEY_LEN => check!(AES128, AES128_KEY_LEN, SecurityStrength::_128bit),
                AES192_KEY_LEN => check!(AES192, AES192_KEY_LEN, SecurityStrength::_192bit),
                AES256_KEY_LEN => check!(AES256, AES256_KEY_LEN, SecurityStrength::_256bit),
                len => panic!("tcId {}: unexpected ACVP key length {len}", self.tc_id),
            }

            self.pt.len() / BLOCK_LEN
        }
    }

    #[test]
    fn acvp_aes_ecb() {
        let contents = match get_test_data("AES", "ACVP-AES-ECB", "rsp") {
            Ok(contents) => contents,
            Err(()) => return,
        };

        let (test_cases, skipped) = EcbTestCase::parse(contents);

        let num_test_cases = test_cases.len();
        let mut num_blocks = 0_usize;
        for test_case in test_cases {
            num_blocks += test_case.run();
        }

        // A format change that stopped the vectors parsing would otherwise pass having checked none.
        assert!(
            num_test_cases > 2000,
            "only {num_test_cases} ACVP-AES-ECB AFT cases parsed; the set has over 2000, so the \
             harness is no longer reading them correctly"
        );

        println!(
            "acvp_aes_ecb: all {num_test_cases} AFT test cases passed \
             ({num_blocks} blocks, each checked in both directions)."
        );
        if skipped != 0 {
            println!("acvp_aes_ecb: {skipped} Monte Carlo (MCT) cases skipped -- see TODO above.");
        }
    }

    /// Confirms the session these vectors came from is one NIST accepted, so a failed session cannot
    /// quietly become our reference.
    #[test]
    fn acvp_aes_ecb_session_was_accepted_by_nist() {
        let contents = match get_test_data("AES", "ACVP-AES-ECB", "res") {
            Ok(contents) => contents,
            Err(()) => return,
        };

        let json: serde_json::Value =
            serde_json::from_str(&contents).expect("test data is not valid JSON");

        let disposition = json[1]["disposition"].as_str().expect("disposition missing");
        assert_eq!(disposition, "passed", "the ACVP-AES-ECB session did not pass at NIST");

        let results = json[1]["tests"].as_array().expect("tests is not an array");
        for result in results {
            let tc_id = result["tcId"].as_u64().expect("tcId missing");
            let outcome = result["result"].as_str().expect("result missing");
            assert_eq!(outcome, "passed", "NIST recorded tcId {tc_id} as {outcome}");
        }

        println!(
            "acvp_aes_ecb_session_was_accepted_by_nist: {disposition:?}, {} test cases.",
            results.len()
        );
    }
}
