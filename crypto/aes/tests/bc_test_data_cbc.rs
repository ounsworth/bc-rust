//! Test AES-CBC against the bc-test-data repo, expected at "../bc-test-data" relative to the root of
//! this git project. If it is not there, the tests print a warning and pass.
//!
//! Exercises `crypto/aes_tdes_vectors/AES/ACVP-AES-CBC.*.{req,rsp,res}.json`. Unlike the ECB set, a
//! CBC response carries only the answer -- `{tcId, ct}` to encrypt, `{tcId, pt}` to decrypt -- so
//! prompt and response are joined on `tcId` to recover the full `(key, iv, pt, ct)` quadruple. See
//! `bc_test_data.rs` for the ACVP file layout.
//!
//! TODO --  `AES_CBC` is an empty stub, so this harness stops one step short of the cipher: it
//!          locates, parses and validates every vector against its group parameters, then reports
//!          what it skipped. To finish it, fill in [`CbcTestCase::run`] and flip
//!          [`AES_CBC_IS_IMPLEMENTED`]. Nothing else here should need to change.

use bouncycastle_aes::BLOCK_LEN;

/// Flip to `true` once `AES_CBC` exists and [`CbcTestCase::run`] is filled in.
const AES_CBC_IS_IMPLEMENTED: bool = false;

#[cfg(test)]
mod bc_test_data_cbc {
    use super::*;
    use bouncycastle_hex as hex;
    use std::collections::BTreeMap;
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

    /// Matching on `<prefix>.` is what keeps this off the `ACVP-AES-CBC-CS1`/`CS2`/`CS3`
    /// ciphertext-stealing sets, which are a different algorithm.
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

    /* *** ACVP-AES-CBC *** */

    /// `pt` and `ct` are both always populated: whichever the prompt supplied, the other comes from
    /// the response.
    #[derive(Clone)]
    struct CbcTestCase {
        tg_id: u64,
        tc_id: u64,
        direction: String,
        key_len: u64,
        key: Vec<u8>,
        iv: Vec<u8>,
        pt: Vec<u8>,
        ct: Vec<u8>,
    }

    impl CbcTestCase {
        /// Joins prompt and response on `tcId`; returns the AFT cases and the number skipped.
        fn parse(req: String, rsp: String) -> (Vec<Self>, usize) {
            let req: serde_json::Value =
                serde_json::from_str(&req).expect("req data is not valid JSON");
            let rsp: serde_json::Value =
                serde_json::from_str(&rsp).expect("rsp data is not valid JSON");

            let mut answers = BTreeMap::<u64, &serde_json::Value>::new();
            let groups = rsp[1]["testGroups"].as_array().expect("rsp testGroups is not an array");
            for group in groups {
                for test in group["tests"].as_array().expect("rsp tests is not an array") {
                    let tc_id = test["tcId"].as_u64().expect("rsp tcId missing");
                    answers.insert(tc_id, test);
                }
            }

            let mut test_cases = Vec::<Self>::new();
            let mut skipped = 0_usize;

            let groups = req[1]["testGroups"].as_array().expect("req testGroups is not an array");
            for group in groups {
                let tg_id = group["tgId"].as_u64().expect("tgId missing");
                let test_type = group["testType"].as_str().expect("testType missing");
                let direction = group["direction"].as_str().expect("direction missing").to_string();
                let key_len = group["keyLen"].as_u64().expect("keyLen missing");

                for test in group["tests"].as_array().expect("req tests is not an array") {
                    let tc_id = test["tcId"].as_u64().expect("tcId missing");
                    let answer = answers.get(&tc_id).expect("no response for this tcId");

                    // TODO --  Monte Carlo (MCT) cases answer with a 100-entry `resultsArray` and
                    //          need the ACVP chaining algorithm. Skipped and counted for now.
                    if test_type != "AFT" {
                        skipped += 1;
                        continue;
                    }

                    let (pt, ct) = match direction.as_str() {
                        "encrypt" => (test["pt"].as_str(), answer["ct"].as_str()),
                        "decrypt" => (answer["pt"].as_str(), test["ct"].as_str()),
                        other => panic!("tcId {tc_id}: unexpected direction {other:?}"),
                    };

                    test_cases.push(Self {
                        tg_id,
                        tc_id,
                        direction: direction.clone(),
                        key_len,
                        key: hex::decode(test["key"].as_str().expect("key missing"))
                            .expect("key is not valid hex"),
                        iv: hex::decode(test["iv"].as_str().expect("iv missing"))
                            .expect("iv is not valid hex"),
                        pt: hex::decode(pt.expect("pt missing")).expect("pt is not valid hex"),
                        ct: hex::decode(ct.expect("ct missing")).expect("ct is not valid hex"),
                    });
                }
            }

            (test_cases, skipped)
        }

        /// Checks the case against its group's declared parameters. This is the half of the harness
        /// that can be verified before `AES_CBC` exists.
        fn validate(&self) {
            assert_eq!(
                self.key.len() as u64 * 8,
                self.key_len,
                "tgId {} tcId {}: key is {} bits, group declares {}",
                self.tg_id,
                self.tc_id,
                self.key.len() * 8,
                self.key_len
            );
            assert_eq!(
                self.iv.len(),
                BLOCK_LEN,
                "tgId {} tcId {}: CBC IV must be one block, got {} bytes",
                self.tg_id,
                self.tc_id,
                self.iv.len()
            );
            assert_eq!(
                self.pt.len(),
                self.ct.len(),
                "tgId {} tcId {}: pt and ct are different lengths",
                self.tg_id,
                self.tc_id
            );
            assert_ne!(self.pt.len(), 0, "tgId {} tcId {}: empty payload", self.tg_id, self.tc_id);
            assert_eq!(
                self.pt.len() % BLOCK_LEN,
                0,
                "tgId {} tcId {}: payload is not a whole number of blocks",
                self.tg_id,
                self.tc_id
            );
        }

        /// TODO --  Run this case against `AES_CBC`. It wants the streaming [`BlockCipher`] API so
        ///          the caller supplies the IV -- the one-shot `SymmetricCipher::encrypt` generates
        ///          its own, which cannot reproduce a fixed vector. Then assert against `self.ct`
        ///          for an encrypt case and `self.pt` for a decrypt one, and return blocks checked.
        ///
        /// TODO --  These vectors are unpadded whole blocks, so whatever padding scheme CBC ends up
        ///          with has to be bypassable or none of this is checkable. Worth settling before
        ///          that decision is made.
        fn run(&self) -> usize {
            unimplemented!(
                "AES_CBC is not implemented yet; see the CBC item in crypto/aes/aes_dev_plan.md"
            )
        }
    }

    #[test]
    fn acvp_aes_cbc() {
        let req = match get_test_data("AES", "ACVP-AES-CBC", "req") {
            Ok(contents) => contents,
            Err(()) => return,
        };
        let rsp = match get_test_data("AES", "ACVP-AES-CBC", "rsp") {
            Ok(contents) => contents,
            Err(()) => return,
        };

        let (test_cases, skipped) = CbcTestCase::parse(req, rsp);

        let num_test_cases = test_cases.len();
        for test_case in &test_cases {
            test_case.validate();
        }

        // A join that dropped one direction would still parse and validate cleanly.
        let encrypts = test_cases.iter().filter(|t| t.direction == "encrypt").count();
        let decrypts = num_test_cases - encrypts;
        assert_ne!(encrypts, 0, "no encrypt cases were parsed");
        assert_ne!(decrypts, 0, "no decrypt cases were parsed");

        assert!(
            num_test_cases > 2000,
            "only {num_test_cases} ACVP-AES-CBC AFT cases parsed; the set has over 2000, so the \
             harness is no longer reading them correctly"
        );

        if !AES_CBC_IS_IMPLEMENTED {
            println!(
                "acvp_aes_cbc: SKIPPED the cipher checks for all {num_test_cases} AFT cases \
                 ({encrypts} encrypt, {decrypts} decrypt) -- AES_CBC is not implemented yet. The \
                 vectors were located, parsed and validated, so only the cipher call is missing."
            );
            if skipped != 0 {
                println!("acvp_aes_cbc: {skipped} Monte Carlo (MCT) cases also skipped.");
            }
            return;
        }

        let mut num_blocks = 0_usize;
        for test_case in &test_cases {
            num_blocks += test_case.run();
        }

        println!(
            "acvp_aes_cbc: all {num_test_cases} AFT test cases passed \
             ({encrypts} encrypt, {decrypts} decrypt, {num_blocks} blocks)."
        );
        if skipped != 0 {
            println!("acvp_aes_cbc: {skipped} Monte Carlo (MCT) cases skipped -- see TODO above.");
        }
    }

    /// Confirms the session these vectors came from is one NIST accepted.
    #[test]
    fn acvp_aes_cbc_session_was_accepted_by_nist() {
        let contents = match get_test_data("AES", "ACVP-AES-CBC", "res") {
            Ok(contents) => contents,
            Err(()) => return,
        };

        let json: serde_json::Value =
            serde_json::from_str(&contents).expect("test data is not valid JSON");

        let disposition = json[1]["disposition"].as_str().expect("disposition missing");
        assert_eq!(disposition, "passed", "the ACVP-AES-CBC session did not pass at NIST");

        let results = json[1]["tests"].as_array().expect("tests is not an array");
        for result in results {
            let tc_id = result["tcId"].as_u64().expect("tcId missing");
            let outcome = result["result"].as_str().expect("result missing");
            assert_eq!(outcome, "passed", "NIST recorded tcId {tc_id} as {outcome}");
        }

        println!(
            "acvp_aes_cbc_session_was_accepted_by_nist: {disposition:?}, {} test cases.",
            results.len()
        );
    }
}
