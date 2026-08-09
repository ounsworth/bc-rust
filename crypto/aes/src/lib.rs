//! TODO -- crate docs for AES

#![no_std]
#![forbid(unsafe_code)]
// TODO #![forbid(missing_docs)]

// TODO -- here only to suppress annoying warnings during dev. Remove once crate is complete
#![allow(unused)]
// So that we can name types "AES128_GCM" instead of "Aes128_Gcm", which is just wrong.
#![allow(non_camel_case_types)]
// #![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(private_bounds)]

mod aes;
pub mod aux_functions;
pub mod key_schedule;
mod rijnael;
mod sbox;
mod state;

/*** Exported constants ***/
pub use aes::{AES_CBC, AES128_CBC, AES192_CBC, AES256_CBC};
pub use aes::{AES_GCM, AES128_GCM, AES192_GCM, AES256_GCM};
pub use aes::{AES128Key, AES192Key, AES256Key};
