//! types used in payencode

use num::bigint::BigUint;
use std::{error, fmt};
use utils::convert_bits;

/// Alias for u8 that contains 5-bit values
pub type U5 = u8;

/// Methods for Vec<U5>
pub struct VecU5;

impl VecU5 {
    /// convert a vector of 5-bit values to hex-string
    pub fn to_hex(bytes: &Vec<U5>) -> String {
        let u5 = bytes.iter().fold(BigUint::from(0u64), |mut s, b| {
            s <<= 5;
            s |= BigUint::from(*b);
            s
        });
        u5.to_str_radix(16)
    }
    /// Convert a vector containing u5 values to u8
    pub fn to_u8(bytes: &Vec<U5>) -> ConvertResult {
        convert_bits(bytes, 5, 8, false)
    }
}

/// Methods for Vec<u8>
pub struct VecU8;

impl VecU8 {
    /// Convert a vector containing u8 values to u5
    pub fn to_u5(bytes: &Vec<U5>) -> ConvertResult {
        convert_bits(bytes, 8, 5, false)
    }
}




/// Result of vector base conversion
pub type ConvertResult = Result<Vec<u8>, BitConversionError>;

/// Error types during bit conversion
#[derive(PartialEq, Debug)]
pub enum BitConversionError {
    /// Input value exceeds "from bits" size
    InvalidInputValue(u8),
    /// Invalid padding values in data
    InvalidPadding,
}

impl fmt::Display for BitConversionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            BitConversionError::InvalidInputValue(b) => write!(f, "invalid input value ({})", b),
            BitConversionError::InvalidPadding => write!(f, "invalid padding"),
        }
    }
}

impl error::Error for BitConversionError {
    fn description(&self) -> &str {
        match *self {
            BitConversionError::InvalidInputValue(_) => "invalid input value",
            BitConversionError::InvalidPadding => "invalid padding",
        }
    }
}
#[test]
fn u5_test() {
    let u5_vec = vec![
        14, 20, 15, 7, 13, 26, 0, 25, 18, 6, 11, 13, 8, 21, 4, 20, 3, 17, 2, 29, 3, 12, 29, 3, 4,
        15, 24, 20, 6, 14, 30, 22,
    ];
    let u8_vec = vec![
        117, 30, 118, 232, 25, 145, 150, 212, 84, 148, 28, 69, 209, 179, 163, 35, 241, 67, 59, 214
    ];

    assert!(VecU5::to_u8(&u5_vec).unwrap().eq(&u8_vec));
    assert!(VecU8::to_u5(&u8_vec).unwrap().eq(&u5_vec));
}
