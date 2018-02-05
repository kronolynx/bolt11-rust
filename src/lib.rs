#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]

/// Lightning Payments Example Implementation
///
/// This is an implementation of
/// [Lightning BOLT11 Specification](https://github.com/lightningnetwork/lightning-rfc/blob/master/11-payment-encoding.md)
/// for providing a minimal QR-code-ready format for requesting lightning payments.
extern crate num;
extern crate hex;
extern crate bech32;
mod lnaddr;





