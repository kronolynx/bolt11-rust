//! types used in payencode

use num::bigint::BigUint;
use std::{error, fmt};
use std::io;
use utils::convert_bits;
use std::num;

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
    pub fn to_u8_vec(bytes: &Vec<U5>) -> ConvertResult {
        convert_bits(bytes, 5, 8, true)
    }
    /// Convert a vector containing u8 values to u5
    pub fn from_u8_vec(bytes: &Vec<u8>) -> ConvertResult {
        convert_bits(bytes, 8, 5, true)
    }

    /// Convert a long to a vector containing u5 values
    pub fn from_u64(value: u64) -> Vec<U5> {
        let mut acc = Vec::<U5>::new();
        let mut val = value;
        while val > 0 {
            acc.push((val % 32) as U5);
            val /= 32;
        }
        acc.reverse();
        acc
    }
}

/// Result of vector base conversion
pub type ConvertResult = Result<Vec<u8>, Error>;

/// Error types
#[derive(Debug)]
pub enum Error {
    /// Input value exceeds "from bits" size
    InvalidInputValue(u8),
    /// Invalid padding values in data
    InvalidPadding,
    /// Invalid input length
    InvalidLength(String),
    /// Wraps an io error produced when reading or writing
    IOErr(io::Error),
    /// Wraps parse float error
    ParseFloatErr(num::ParseFloatError)
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InvalidInputValue(b) => write!(f, "invalid input value ({})", b),
            Error::InvalidPadding => write!(f, "invalid padding"),
            Error::InvalidLength(ref e) => write!(f, "{}", e),
            Error::IOErr(ref e) => write!(f, "{}", e),
            Error::ParseFloatErr(ref e) => write!(f, "{}", e),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::InvalidInputValue(_) => "invalid input value",
            Error::InvalidPadding => "invalid padding",
            Error::InvalidLength(ref e) => e,
            Error::IOErr(ref e) => error::Error::description(e),
            Error::ParseFloatErr(ref e) => error::Error::description(e),
        }
    }
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::IOErr(ref e) => Some(e),
            Error::ParseFloatErr(ref e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::IOErr(e)
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

    assert!(VecU5::to_u8_vec(&u5_vec).unwrap().eq(&u8_vec));
    assert!(VecU5::from_u8_vec(&u8_vec).unwrap().eq(&u5_vec));
}
