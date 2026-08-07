//! TODO -- crate docs for AES

#![no_std]
#![forbid(unsafe_code)]
// TODO #![forbid(missing_docs)]

// TODO -- here only to suppress annoying warnings during dev. Remove once crate is complete
#![allow(unused)]
// These are because the code is matching variable names exactly against FIPS 204, for example both 'K' and 'k',
// or 'A' and 'a' are used and have specific meanings.
// But need to tell the rust linter to not care.
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

pub mod aux_functions;
pub mod key_schedule;
mod rijnael;
mod state;
mod sub_bytes;

/*** Exported constants ***/
pub use state::AES_BLOCK_LEN;
