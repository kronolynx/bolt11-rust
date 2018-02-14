//! types used in payencode

use num::bigint::BigUint;
use std::{error, fmt};

///Vector containing 5-bit values
pub struct VecU5(Vec<u8>);

impl fmt::Display for VecU5 {
    fn fmt(&self, fmtr: &mut fmt::Formatter) -> fmt::Result {
        write!(fmtr, "{}", &self.to_hex())?;
        Ok(())
    }
}

impl VecU5 {
    fn val(&self) -> &Vec<u8> {
        &self.0
    }
    /// convert a vector of 5-bit values to hex-string
    fn to_hex(&self) -> String {
        let u5 = &self.0.iter().fold(BigUint::from(0u64), |mut s, b| {
            s <<= 5;
            s |= BigUint::from(*b);
            s
        });
        u5.to_str_radix(16)
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
