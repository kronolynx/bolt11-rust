#![warn(missing_docs)]
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]

//! Lightning Payments Example Implementation
//!
//! This is an implementation of
//! [Lightning BOLT11 Specification](https://github.com/lightningnetwork/lightning-rfc/blob/master/11-payment-encoding.md)
//! for providing a minimal QR-code-ready format for requesting lightning payments.

extern crate byteorder;
extern crate crypto;
extern crate hex;
extern crate itertools;
#[macro_use]
extern crate lazy_static;
extern crate num;
extern crate secp256k1;

#[macro_use]
mod macros;
mod timestamp;
mod utils;
mod types;
mod tag;
mod amount;
mod bech32;
mod payment_request;
