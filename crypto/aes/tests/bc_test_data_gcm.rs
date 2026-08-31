//! Test AES-GCM against the bc-test-data repo, expected at "../bc-test-data" relative to the root of
//! this git project. If it is not there, the tests print a warning and pass.
//!
//! Exercises `crypto/aes_tdes_vectors/GCM/ACVP-AES-GCM.*.{req,rsp,res}.json`. Prompt and response are
//! joined on `tcId`. Responses come in three shapes, and the third is the one that matters:
//!
//!  * encrypt -> `{tcId, ct, tag}` (135 cases)
//!  * decrypt, tag valid -> `{tcId, pt}` (106 cases)
//!  * decrypt, tag forged -> `{tcId, testPassed: false}`, ie the tag check must fail (29 cases)
//!
//! A GCM that ignored its tag entirely would pass the other 241, so those 29 are the load-bearing
//! ones. See `bc_test_data.rs` for the ACVP file layout.
//!
//! TODO --  `AES_GCM` is an empty stub, so this harness stops one step short of the cipher: it
//!          locates, parses and validates every vector against its group parameters, then reports
//!          what it skipped. To finish it, fill in [`GcmTestCase::run`] and flip
//!          [`AES_GCM_IS_IMPLEMENTED`].
//!
//! TODO --  `ACVP-AES-GMAC` sits in the same directory: the same algorithm with an empty payload,
//!          authentication only. It wants a sibling harness once GCM works.

use bouncycastle_aes::BLOCK_LEN;

/// Flip to `true` once `AES_GCM` exists and [`GcmTestCase::run`] is filled in.
const AES_GCM_IS_IMPLEMENTED: bool = false;

#[cfg(test)]
mod bc_test_data_gcm {
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

    /// Matching on `<prefix>.` is what keeps `ACVP-AES-GCM` off `ACVP-AES-GMAC`.
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

    /* *** ACVP-AES-GCM *** */

    /// What a case expects to happen.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Expected {
        /// Produce exactly this `ct` and `tag`.
        Ciphertext,
        /// Recover exactly this `pt`.
        Plaintext,
        /// Reject it. `pt` is meaningless and must not be trusted or returned.
        TagCheckFailure,
    }

    #[derive(Clone)]
    struct GcmTestCase {
        tg_id: u64,
        tc_id: u64,
        expected: Expected,
        key_len: u64,
        iv_len: u64,
        aad_len: u64,
        payload_len: u64,
        tag_len: u64,
        key: Vec<u8>,
        iv: Vec<u8>,
        aad: Vec<u8>,
        pt: Vec<u8>,
        ct: Vec<u8>,
        tag: Vec<u8>,
    }

    impl GcmTestCase {
        /// Joins prompt and response on `tcId`.
        fn parse(req: String, rsp: String) -> Vec<Self> {
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

            let groups = req[1]["testGroups"].as_array().expect("req testGroups is not an array");
            for group in groups {
                let tg_id = group["tgId"].as_u64().expect("tgId missing");
                let direction = group["direction"].as_str().expect("direction missing");

                // An empty aad or payload is omitted rather than given as "".
                let hex_field = |v: &serde_json::Value, name: &str| -> Vec<u8> {
                    match v[name].as_str() {
                        Some(s) => hex::decode(s).expect("field is not valid hex"),
                        None => Vec::new(),
                    }
                };

                for test in group["tests"].as_array().expect("req tests is not an array") {
                    let tc_id = test["tcId"].as_u64().expect("tcId missing");
                    let answer = answers.get(&tc_id).expect("no response for this tcId");

                    let expected = match direction {
                        "encrypt" => Expected::Ciphertext,
                        "decrypt" => match answer["testPassed"].as_bool() {
                            Some(false) => Expected::TagCheckFailure,
                            _ => Expected::Plaintext,
                        },
                        other => panic!("tcId {tc_id}: unexpected direction {other:?}"),
                    };

                    let (pt, ct, tag) = match expected {
                        Expected::Ciphertext => (
                            hex_field(test, "pt"),
                            hex_field(answer, "ct"),
                            hex_field(answer, "tag"),
                        ),
                        Expected::Plaintext => {
                            (hex_field(answer, "pt"), hex_field(test, "ct"), hex_field(test, "tag"))
                        }
                        // Nothing to recover -- the prompt's ct/tag are the forgery to reject.
                        Expected::TagCheckFailure => {
                            (Vec::new(), hex_field(test, "ct"), hex_field(test, "tag"))
                        }
                    };

                    test_cases.push(Self {
                        tg_id,
                        tc_id,
                        expected,
                        key_len: group["keyLen"].as_u64().expect("keyLen missing"),
                        iv_len: group["ivLen"].as_u64().expect("ivLen missing"),
                        aad_len: group["aadLen"].as_u64().expect("aadLen missing"),
                        payload_len: group["payloadLen"].as_u64().expect("payloadLen missing"),
                        tag_len: group["tagLen"].as_u64().expect("tagLen missing"),
                        key: hex_field(test, "key"),
                        iv: hex_field(test, "iv"),
                        aad: hex_field(test, "aad"),
                        pt,
                        ct,
                        tag,
                    });
                }
            }

            test_cases
        }

        /// Checks the case against its group's declared parameters. This is the half of the harness
        /// that can be verified before `AES_GCM` exists.
        fn validate(&self) {
            let bits = |v: &[u8]| v.len() as u64 * 8;
            let where_ = format!("tgId {} tcId {}", self.tg_id, self.tc_id);

            assert_eq!(bits(&self.key), self.key_len, "{where_}: key length");
            assert_eq!(bits(&self.iv), self.iv_len, "{where_}: iv length");
            assert_eq!(bits(&self.aad), self.aad_len, "{where_}: aad length");
            assert_eq!(bits(&self.tag), self.tag_len, "{where_}: tag length");

            // GCM is a stream construction, so the payload is not block-aligned in general -- these
            // vectors include 64-bit payloads.
            assert_eq!(bits(&self.ct), self.payload_len, "{where_}: ct length");
            match self.expected {
                Expected::Ciphertext | Expected::Plaintext => {
                    assert_eq!(bits(&self.pt), self.payload_len, "{where_}: pt length");
                }
                Expected::TagCheckFailure => {
                    assert!(
                        self.pt.is_empty(),
                        "{where_}: a rejected case must carry no plaintext"
                    );
                }
            }

            // TODO --  This set is all 96-bit IVs, the one length GCM handles without running the
            //          nonce through GHASH. Other lengths need the other branch of the J0
            //          derivation; this assertion is the early warning if they ever appear.
            assert_eq!(self.iv_len, 96, "{where_}: unexpected IV length {}", self.iv_len);

            // A tag shorter than a block is a truncated tag: legal in SP 800-38D, separate path.
            assert!(
                self.tag_len == 96 || self.tag_len == 128,
                "{where_}: unexpected tag length {}",
                self.tag_len
            );
            assert!(self.tag.len() <= BLOCK_LEN, "{where_}: tag is longer than one block");
        }

        /// TODO --  Run this case against `AES_GCM`:
        ///          * [`Expected::Ciphertext`] -- assert `ct` and `tag` (tags may be truncated, so
        ///            compare only `self.tag.len()` bytes).
        ///          * [`Expected::Plaintext`] -- assert the recovered `pt`.
        ///          * [`Expected::TagCheckFailure`] -- assert `Err(AEADTagCheckFailed)` specifically,
        ///            not just any error, and never look at any plaintext produced along the way.
        ///
        /// TODO --  The encrypt path needs an explicit-nonce entry point. `AEADCipher::aead_encrypt`
        ///          generates its own nonce and so cannot reproduce a fixed vector -- the same gap
        ///          the mlkem harness works around with `encaps_internal`.
        fn run(&self) {
            unimplemented!(
                "AES_GCM is not implemented yet; see the GCM item in crypto/aes/aes_dev_plan.md"
            )
        }
    }

    #[test]
    fn acvp_aes_gcm() {
        let req = match get_test_data("GCM", "ACVP-AES-GCM", "req") {
            Ok(contents) => contents,
            Err(()) => return,
        };
        let rsp = match get_test_data("GCM", "ACVP-AES-GCM", "rsp") {
            Ok(contents) => contents,
            Err(()) => return,
        };

        let test_cases = GcmTestCase::parse(req, rsp);

        let num_test_cases = test_cases.len();
        for test_case in &test_cases {
            test_case.validate();
        }

        let count = |want: Expected| test_cases.iter().filter(|t| t.expected == want).count();
        let encrypts = count(Expected::Ciphertext);
        let decrypts = count(Expected::Plaintext);
        let forgeries = count(Expected::TagCheckFailure);

        assert!(
            num_test_cases > 200,
            "only {num_test_cases} ACVP-AES-GCM cases parsed; the set has 270, so the harness is no \
             longer reading them correctly"
        );
        assert_ne!(encrypts, 0, "no encrypt cases were parsed");
        assert_ne!(decrypts, 0, "no valid-tag decrypt cases were parsed");
        assert_ne!(
            forgeries, 0,
            "no invalid-tag cases were parsed -- these are the important ones"
        );

        if !AES_GCM_IS_IMPLEMENTED {
            println!(
                "acvp_aes_gcm: SKIPPED the cipher checks for all {num_test_cases} AFT cases \
                 ({encrypts} encrypt, {decrypts} decrypt, {forgeries} tag-forgery) -- AES_GCM is \
                 not implemented yet. The vectors were located, parsed and validated, so only the \
                 cipher call is missing."
            );
            return;
        }

        for test_case in &test_cases {
            test_case.run();
        }

        println!(
            "acvp_aes_gcm: all {num_test_cases} AFT test cases passed \
             ({encrypts} encrypt, {decrypts} decrypt, {forgeries} tag-forgery)."
        );
    }

    /// Confirms the session these vectors came from is one NIST accepted. For GCM that includes the
    /// 29 cases whose expected outcome is a rejection -- "passed" there means the submitting
    /// implementation correctly refused them.
    #[test]
    fn acvp_aes_gcm_session_was_accepted_by_nist() {
        let contents = match get_test_data("GCM", "ACVP-AES-GCM", "res") {
            Ok(contents) => contents,
            Err(()) => return,
        };

        let json: serde_json::Value =
            serde_json::from_str(&contents).expect("test data is not valid JSON");

        let disposition = json[1]["disposition"].as_str().expect("disposition missing");
        assert_eq!(disposition, "passed", "the ACVP-AES-GCM session did not pass at NIST");

        let results = json[1]["tests"].as_array().expect("tests is not an array");
        for result in results {
            let tc_id = result["tcId"].as_u64().expect("tcId missing");
            let outcome = result["result"].as_str().expect("result missing");
            assert_eq!(outcome, "passed", "NIST recorded tcId {tc_id} as {outcome}");
        }

        println!(
            "acvp_aes_gcm_session_was_accepted_by_nist: {disposition:?}, {} test cases.",
            results.len()
        );
    }
}
