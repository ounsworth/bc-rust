//! Test the AES block cipher against the bc-test-data repo, expected at "../bc-test-data" relative
//! to the root of this git project. If it is not there, the tests print a warning and pass.
//!
//! Exercises `crypto/aes_tdes_vectors/AES/ACVP-AES-ECB.*.{req,rsp,res}.json`. An ACVP-AES-ECB AFT
//! vector is a known-answer test for the raw FIPS 197 permutation: one key, one block in, one block
//! out. This crate does not implement ECB -- the harness drives the permutation directly.
//!
//! The ECB Monte Carlo Tests (MCTs) are different: each checkpoint performs 1,000 chained AES
//! operations, then derives the key for the next checkpoint from the last one or two outputs.
//! The request file supplies the direction (`encrypt` or `decrypt`), while the response file supplies
//! the 100-entry `resultsArray` containing the expected checkpoints.
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
    use std::collections::HashMap;
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

        // Just print once.
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

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Direction {
        Encrypt,
        Decrypt,
    }

    impl Direction {
        fn parse(value: &str) -> Self {
            match value {
                "encrypt" => Self::Encrypt,
                "decrypt" => Self::Decrypt,
                other => panic!("unexpected ACVP direction {other:?}"),
            }
        }

        fn as_str(self) -> &'static str {
            match self {
                Self::Encrypt => "encrypt",
                Self::Decrypt => "decrypt",
            }
        }
    }

    /// An AFT response carries the whole `(key, pt, ct)` triple, and `ct = CIPHER(key, pt)` holds
    /// whichever direction the prompt asked for, so every AFT case can still be checked both ways.
    #[derive(Clone)]
    struct EcbTestCase {
        tg_id: u64,
        tc_id: u64,
        key: Vec<u8>,
        pt: Vec<u8>,
        ct: Vec<u8>,
    }

    /// One of the 100 checkpoints emitted by an AES ECB Monte Carlo Test.
    ///
    /// `key` is the key at the start of this checkpoint. For encryption, `pt` is the first input
    /// block and `ct` is the output after 1,000 chained encryptions. For decryption, those roles are
    /// reversed.
    #[derive(Clone)]
    struct EcbMctResult {
        key: Vec<u8>,
        pt: Vec<u8>,
        ct: Vec<u8>,
    }

    /// Initial MCT values taken from the ACVP request file.
    #[derive(Clone)]
    struct EcbMctInitial {
        key: Vec<u8>,
        input: Vec<u8>,
    }

    /// One complete ECB Monte Carlo test.
    struct EcbMctTestCase {
        tg_id: u64,
        tc_id: u64,
        direction: Direction,
        initial: EcbMctInitial,
        results: Vec<EcbMctResult>,
    }

    impl EcbTestCase {
        /// Parses both AFT and MCT cases.
        ///
        /// The response file supplies the expected results. MCT direction and initial values are
        /// taken from the request file and joined to the response by `(tgId, tcId)`.
        fn parse(
            request_data: String,
            response_data: String,
        ) -> (Vec<Self>, Vec<EcbMctTestCase>) {
            let request: serde_json::Value =
                serde_json::from_str(&request_data).expect("request test data is not valid JSON");

            let response: serde_json::Value =
                serde_json::from_str(&response_data).expect("response test data is not valid JSON");

            let request_groups = request[1]["testGroups"]
                .as_array()
                .expect("request testGroups is not an array");

            let mut mct_directions = HashMap::<u64, Direction>::new();
            let mut mct_initials = HashMap::<(u64, u64), EcbMctInitial>::new();

            for group in request_groups {
                let tg_id = group["tgId"].as_u64().expect("request tgId missing");

                if group["testType"].as_str() != Some("MCT") {
                    continue;
                }

                let direction = Direction::parse(
                    group["direction"]
                        .as_str()
                        .expect("MCT request direction missing"),
                );

                mct_directions.insert(tg_id, direction);

                let tests = group["tests"]
                    .as_array()
                    .expect("MCT request tests is not an array");

                for test in tests {
                    let tc_id = test["tcId"].as_u64().expect("MCT request tcId missing");

                    let key = hex::decode(
                        test["key"]
                            .as_str()
                            .expect("MCT request key missing"),
                    )
                    .expect("MCT request key is not valid hex");

                    let input_hex = match direction {
                        Direction::Encrypt => test["pt"]
                            .as_str()
                            .expect("encrypt MCT request pt missing"),
                        Direction::Decrypt => test["ct"]
                            .as_str()
                            .expect("decrypt MCT request ct missing"),
                    };

                    let input =
                        hex::decode(input_hex).expect("MCT request input is not valid hex");

                    mct_initials.insert((tg_id, tc_id), EcbMctInitial { key, input });
                }
            }

            let response_groups = response[1]["testGroups"]
                .as_array()
                .expect("response testGroups is not an array");

            let mut aft_cases = Vec::<Self>::new();
            let mut mct_cases = Vec::<EcbMctTestCase>::new();

            for group in response_groups {
                let tg_id = group["tgId"].as_u64().expect("response tgId missing");
                let tests = group["tests"]
                    .as_array()
                    .expect("response tests is not an array");

                for test in tests {
                    let tc_id = test["tcId"].as_u64().expect("response tcId missing");

                    if let Some(results_array) = test["resultsArray"].as_array() {
                        let direction = *mct_directions
                            .get(&tg_id)
                            .unwrap_or_else(|| panic!("tgId {tg_id}: MCT direction not found in req"));

                        let initial = mct_initials
                            .get(&(tg_id, tc_id))
                            .unwrap_or_else(|| {
                                panic!(
                                    "tgId {tg_id} tcId {tc_id}: MCT initial values not found in req"
                                )
                            })
                            .clone();

                        let results = results_array
                            .iter()
                            .map(|result| EcbMctResult {
                                key: hex::decode(
                                    result["key"]
                                        .as_str()
                                        .expect("MCT result key missing"),
                                )
                                .expect("MCT result key is not valid hex"),

                                pt: hex::decode(
                                    result["pt"]
                                        .as_str()
                                        .expect("MCT result pt missing"),
                                )
                                .expect("MCT result pt is not valid hex"),

                                ct: hex::decode(
                                    result["ct"]
                                        .as_str()
                                        .expect("MCT result ct missing"),
                                )
                                .expect("MCT result ct is not valid hex"),
                            })
                            .collect::<Vec<_>>();

                        assert_eq!(
                            results.len(),
                            100,
                            "tgId {tg_id} tcId {tc_id}: MCT resultsArray has {} entries, expected 100",
                            results.len()
                        );

                        mct_cases.push(EcbMctTestCase {
                            tg_id,
                            tc_id,
                            direction,
                            initial,
                            results,
                        });

                        continue;
                    }

                    match (
                        test["key"].as_str(),
                        test["pt"].as_str(),
                        test["ct"].as_str(),
                    ) {
                        (Some(key), Some(pt), Some(ct)) => aft_cases.push(Self {
                            tg_id,
                            tc_id,
                            key: hex::decode(key).expect("AFT key is not valid hex"),
                            pt: hex::decode(pt).expect("AFT pt is not valid hex"),
                            ct: hex::decode(ct).expect("AFT ct is not valid hex"),
                        }),

                        _ => panic!(
                            "tgId {tg_id} tcId {tc_id}: unrecognized ACVP ECB response shape"
                        ),
                    }
                }
            }

            (aft_cases, mct_cases)
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
                    let engine =
                        <$engine>::new(&key).expect("AES::new() rejected an ACVP key");

                    // Some AFT payloads contain multiple blocks. ECB means every block is processed
                    // independently under the same key.
                    for (i, (pt, ct)) in self
                        .pt
                        .chunks_exact(BLOCK_LEN)
                        .zip(self.ct.chunks_exact(BLOCK_LEN))
                        .enumerate()
                    {
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
                AES128_KEY_LEN => {
                    check!(AES128, AES128_KEY_LEN, SecurityStrength::_128bit)
                }
                AES192_KEY_LEN => {
                    check!(AES192, AES192_KEY_LEN, SecurityStrength::_192bit)
                }
                AES256_KEY_LEN => {
                    check!(AES256, AES256_KEY_LEN, SecurityStrength::_256bit)
                }
                len => panic!("tcId {}: unexpected ACVP key length {len}", self.tc_id),
            }

            self.pt.len() / BLOCK_LEN
        }
    }

    impl EcbMctTestCase {
        /// Derives the key for the next ACVP MCT checkpoint.
        ///
        /// NIST's AES Monte Carlo key shuffle is:
        ///
        /// AES-128:
        ///     next_key = key XOR output[999]
        ///
        /// AES-192:
        ///     next_key = key XOR (LSB64(output[998]) || output[999])
        ///
        /// AES-256:
        ///     next_key = key XOR (output[998] || output[999])
        ///
        /// `output` means ciphertext during encryption and plaintext during decryption.
        fn next_key(
            key: &[u8],
            penultimate: &[u8; BLOCK_LEN],
            final_block: &[u8; BLOCK_LEN],
        ) -> Vec<u8> {
            let mut shuffle = Vec::with_capacity(key.len());

            match key.len() {
                AES128_KEY_LEN => {
                    shuffle.extend_from_slice(final_block);
                }

                AES192_KEY_LEN => {
                    // The least-significant 64 bits are the final 8 bytes of the 128-bit block.
                    shuffle.extend_from_slice(&penultimate[BLOCK_LEN - 8..]);
                    shuffle.extend_from_slice(final_block);
                }

                AES256_KEY_LEN => {
                    shuffle.extend_from_slice(penultimate);
                    shuffle.extend_from_slice(final_block);
                }

                len => panic!("unexpected MCT AES key length {len}"),
            }

            assert_eq!(
                shuffle.len(),
                key.len(),
                "MCT key-shuffle material has the wrong length"
            );

            key.iter()
                .zip(shuffle.iter())
                .map(|(key_byte, shuffle_byte)| key_byte ^ shuffle_byte)
                .collect()
        }

        /// Runs one 1,000-operation MCT checkpoint.
        ///
        /// The AES block operation is in-place, which naturally implements the ECB MCT chaining:
        /// the output of operation `j` is already the input to operation `j + 1`.
        fn run_checkpoint(
            &self,
            key: &[u8],
            input: &[u8],
        ) -> ([u8; BLOCK_LEN], [u8; BLOCK_LEN]) {
            assert_eq!(
                input.len(),
                BLOCK_LEN,
                "tgId {} tcId {}: MCT input is not one AES block",
                self.tg_id,
                self.tc_id
            );

            let mut block: [u8; BLOCK_LEN] = input.try_into().unwrap();
            let mut penultimate = [0_u8; BLOCK_LEN];
            let mut final_block = [0_u8; BLOCK_LEN];

            macro_rules! run {
                ($engine:ty, $key_len:expr, $strength:expr) => {{
                    let key_material = key_material_from::<$key_len>(key, $strength);
                    let engine = <$engine>::new(&key_material)
                        .expect("AES::new() rejected an ACVP MCT key");

                    for j in 0..1000 {
                        match self.direction {
                            Direction::Encrypt => engine.encrypt_block(&mut block),
                            Direction::Decrypt => engine.decrypt_block(&mut block),
                        }

                        if j == 998 {
                            penultimate = block;
                        } else if j == 999 {
                            final_block = block;
                        }
                    }
                }};
            }

            match key.len() {
                AES128_KEY_LEN => {
                    run!(AES128, AES128_KEY_LEN, SecurityStrength::_128bit)
                }
                AES192_KEY_LEN => {
                    run!(AES192, AES192_KEY_LEN, SecurityStrength::_192bit)
                }
                AES256_KEY_LEN => {
                    run!(AES256, AES256_KEY_LEN, SecurityStrength::_256bit)
                }
                len => panic!(
                    "tgId {} tcId {}: unexpected MCT key length {len}",
                    self.tg_id, self.tc_id
                ),
            }

            (penultimate, final_block)
        }

        /// Runs and verifies all 100 MCT checkpoints.
        ///
        /// Every checkpoint performs 1,000 AES operations. The final output is compared with the
        /// ACVP response, then the next key is derived with the ACVP key shuffle. The derived key
        /// and input are checked against the next response checkpoint instead of blindly trusting
        /// the response's supplied values.
        ///
        /// Returns the number of AES block operations performed.
        fn run(&self) -> usize {
            assert_eq!(
                self.results.len(),
                100,
                "tgId {} tcId {}: expected 100 MCT checkpoints",
                self.tg_id,
                self.tc_id
            );

            let first = self
                .results
                .first()
                .expect("MCT resultsArray unexpectedly empty");

            assert_eq!(
                first.key,
                self.initial.key,
                "tgId {} tcId {}: first MCT checkpoint key differs from request",
                self.tg_id,
                self.tc_id
            );

            let first_input = match self.direction {
                Direction::Encrypt => &first.pt,
                Direction::Decrypt => &first.ct,
            };

            assert_eq!(
                first_input,
                &self.initial.input,
                "tgId {} tcId {}: first MCT checkpoint input differs from request",
                self.tg_id,
                self.tc_id
            );

            let mut current_key = self.initial.key.clone();
            let mut current_input = self.initial.input.clone();

            for (iteration, expected) in self.results.iter().enumerate() {
                assert_eq!(
                    current_key,
                    expected.key,
                    "{}: tgId {} tcId {} MCT iteration {iteration}: derived key does not match \
                     response checkpoint",
                    self.direction.as_str(),
                    self.tg_id,
                    self.tc_id
                );

                let expected_input = match self.direction {
                    Direction::Encrypt => &expected.pt,
                    Direction::Decrypt => &expected.ct,
                };

                assert_eq!(
                    &current_input,
                    expected_input,
                    "{}: tgId {} tcId {} MCT iteration {iteration}: chained input does not match \
                     response checkpoint",
                    self.direction.as_str(),
                    self.tg_id,
                    self.tc_id
                );

                let (penultimate, final_block) =
                    self.run_checkpoint(&current_key, &current_input);

                let expected_output = match self.direction {
                    Direction::Encrypt => &expected.ct,
                    Direction::Decrypt => &expected.pt,
                };

                assert_eq!(
                    &final_block[..],
                    expected_output,
                    "{}: tgId {} tcId {} MCT iteration {iteration}: final output after 1000 AES \
                     operations differs from ACVP response",
                    self.direction.as_str(),
                    self.tg_id,
                    self.tc_id
                );

                current_key =
                    Self::next_key(&current_key, &penultimate, &final_block);

                // ECB MCT feeds the final output of this checkpoint into the first operation of the
                // next checkpoint.
                current_input = final_block.to_vec();
            }

            self.results.len() * 1000
        }
    }

    #[test]
    fn acvp_aes_ecb() {
        let request_contents = match get_test_data("AES", "ACVP-AES-ECB", "req") {
            Ok(contents) => contents,
            Err(()) => return,
        };

        let response_contents = match get_test_data("AES", "ACVP-AES-ECB", "rsp") {
            Ok(contents) => contents,
            Err(()) => return,
        };

        let (aft_cases, mct_cases) =
            EcbTestCase::parse(request_contents, response_contents);

        let num_aft_cases = aft_cases.len();
        let mut num_aft_blocks = 0_usize;

        for test_case in aft_cases {
            num_aft_blocks += test_case.run();
        }

        // A format change that stopped the vectors parsing would otherwise pass having checked none.
        assert!(
            num_aft_cases > 2000,
            "only {num_aft_cases} ACVP-AES-ECB AFT cases parsed; the set has over 2000, so the \
             harness is no longer reading them correctly"
        );

        assert!(
            !mct_cases.is_empty(),
            "no ACVP-AES-ECB MCT cases parsed; the harness is no longer reading them correctly"
        );

        let num_mct_cases = mct_cases.len();
        let mut num_mct_operations = 0_usize;

        for test_case in mct_cases {
            num_mct_operations += test_case.run();
        }

        println!(
            "acvp_aes_ecb: all {num_aft_cases} AFT test cases passed \
             ({num_aft_blocks} blocks, each checked in both directions)."
        );

        println!(
            "acvp_aes_ecb: all {num_mct_cases} MCT test cases passed \
             ({num_mct_operations} chained AES block operations)."
        );
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

        let disposition = json[1]["disposition"]
            .as_str()
            .expect("disposition missing");

        assert_eq!(
            disposition, "passed",
            "the ACVP-AES-ECB session did not pass at NIST"
        );

        let results = json[1]["tests"]
            .as_array()
            .expect("tests is not an array");

        for result in results {
            let tc_id = result["tcId"].as_u64().expect("tcId missing");
            let outcome = result["result"].as_str().expect("result missing");

            assert_eq!(
                outcome, "passed",
                "NIST recorded tcId {tc_id} as {outcome}"
            );
        }

        println!(
            "acvp_aes_ecb_session_was_accepted_by_nist: {disposition:?}, {} test cases.",
            results.len()
        );
    }
}