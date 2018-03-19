//! types used in payencode

use num::bigint::BigUint;
use std::{error, fmt};
use std::io;
use utils::convert_bits;
use std::num;
use std::string;
use bech32;
use secp256k1;
use std::fmt::Write;

/// Alias for u8 that contains 5-bit values
pub type U5 = u8;

pub trait U5Conversions {
    /// convert a vector of 5-bit values to hex-string
    fn u5_to_hex(&self) -> String;
    /// Convert a vector containing u5 values to u8
    fn to_u8_vec(&self, padding: bool) -> ConvertResult;
    /// Convert a vector of u5 values to u64
    fn u5_vec_to_u64(&self, length: usize) -> u64;
}

impl U5Conversions for Vec<U5> {
    /// convert a vector of 5-bit values to hex-string
    fn u5_to_hex(&self) -> String {
        let u5 = self.iter().fold(BigUint::from(0u64), |mut s, b| {
            s <<= 5;
            s |= BigUint::from(*b);
            s
        });
        u5.to_str_radix(16)
    }
    /// Convert a vector containing u5 values to u8
    fn to_u8_vec(&self, padding: bool) -> ConvertResult {
        convert_bits(self, 5, 8, padding)
    }
    /// Convert a vector of u5 values to u64
    fn u5_vec_to_u64(&self, length: usize) -> u64 {
        self.iter()
            .take(length)
            .fold(0u64, |acc, i| acc * 32u64 + *i as u64)
    }
}

pub trait U8Conversions {
    /// Convert a vector containing u8 values to u5
    fn to_u5_vec(&self, padding: bool) -> ConvertResult;
    /// Convert a vector of u8 to hex-string
    fn to_hex_string(&self) -> String;
}

impl U8Conversions for Vec<u8> {
    /// Convert a vector containing u8 values to u5
    fn to_u5_vec(&self, padding: bool) -> ConvertResult {
        convert_bits(self, 8, 5, padding)
    }
    /// Convert a vector of u8 to hex-string
    fn to_hex_string(&self) -> String {
        self.iter().fold(String::new(), |mut acc: String, b: &u8| {
            write!(&mut acc, "{:02x}", b).expect("Unable to write");
            acc
        })
    }
}

pub trait StringConversions {
    /// Convert a hex string to bytes
    fn hex_to_bytes(&self) -> Result<Vec<u8>, num::ParseIntError>;
}

impl StringConversions for String {
    fn hex_to_bytes(&self) -> Result<Vec<u8>, num::ParseIntError> {
        /// split a string in chunks, the length of the string must be even
        fn split_n(s: &str, n: usize) -> Vec<&str> {
            (0..(s.len() - n + 1) / 2 + 1)
                .map(|i| &s[2 * i..2 * i + n])
                .collect()
        }

        let padded: String = if self.len() % 2 != 0 {
            let mut s = String::from("0");
            s.push_str(self);
            s
        } else {
            self.to_owned()
        };

        split_n(&padded.trim()[..], 2)
            .iter()
            .map(|b| u8::from_str_radix(b, 16))
            .collect::<Result<Vec<u8>, _>>()
    }
}

pub trait U64VecU5Conversions {
    /// Convert a u64 to a vector containing u5 values
    fn to_u5_vec(&self) -> Vec<U5>;
}

impl U64VecU5Conversions for u64 {
    /// Convert a u64 to a vector containing u5 values
    fn to_u5_vec(&self) -> Vec<U5> {
        let mut acc = Vec::<U5>::new();
        let mut val = *self;
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
    /// Invalid parameter
    InvalidParameter(String),
    /// Input value exceeds "from bits" size
    InvalidInputValue(u8),
    /// Invalid padding values in data
    InvalidPadding,
    /// Invalid input length
    InvalidLength(String),
    /// Wraps an io error produced when reading or writing
    IOErr(io::Error),
    /// Wraps parse float error
    ParseFloatErr(num::ParseFloatError),
    /// Wraps parse int error
    ParseIntErr(num::ParseIntError),
    /// Wraps string from utf8 error
    FromUTF8Err(string::FromUtf8Error),
    /// Wraps bech32 error
    Bech32Err(bech32::Error),
    /// Wraps secp256k1 error
    SignatureError(secp256k1::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InvalidParameter(ref e) => write!(f, "{}", e),
            Error::InvalidInputValue(b) => write!(f, "invalid input value ({})", b),
            Error::InvalidPadding => write!(f, "invalid padding"),
            Error::InvalidLength(ref e) => write!(f, "{}", e),
            Error::IOErr(ref e) => write!(f, "{}", e),
            Error::ParseFloatErr(ref e) => write!(f, "{}", e),
            Error::ParseIntErr(ref e) => write!(f, "{}", e),
            Error::FromUTF8Err(ref e) => write!(f, "{}", e),
            Error::Bech32Err(ref e) => write!(f, "{}", e),
            Error::SignatureError(ref e) => write!(f, "{:?}", e),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::InvalidParameter(ref e) => e,
            Error::InvalidInputValue(_) => "invalid input value",
            Error::InvalidPadding => "invalid padding",
            Error::InvalidLength(ref e) => e,
            Error::IOErr(ref e) => error::Error::description(e),
            Error::ParseFloatErr(ref e) => error::Error::description(e),
            Error::ParseIntErr(ref e) => error::Error::description(e),
            Error::FromUTF8Err(ref e) => error::Error::description(e),
            Error::Bech32Err(ref e) => error::Error::description(e),
            Error::SignatureError(ref e) => match *e {
                secp256k1::Error::InvalidSignature => "invalid signature",
                secp256k1::Error::InvalidPublicKey => "invalid public key",
                secp256k1::Error::InvalidSecretKey => "invalid secret key",
                secp256k1::Error::InvalidRecoveryId => "invalid recovery id",
                secp256k1::Error::InvalidMessage => "invalid message",
            },
        }
    }
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::IOErr(ref e) => Some(e),
            Error::ParseFloatErr(ref e) => Some(e),
            Error::ParseIntErr(ref e) => Some(e),
            Error::FromUTF8Err(ref e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::IOErr(e)
    }
}

impl From<num::ParseFloatError> for Error {
    fn from(e: num::ParseFloatError) -> Error {
        Error::ParseFloatErr(e)
    }
}

impl From<num::ParseIntError> for Error {
    fn from(e: num::ParseIntError) -> Error {
        Error::ParseIntErr(e)
    }
}

impl From<string::FromUtf8Error> for Error {
    fn from(e: string::FromUtf8Error) -> Error {
        Error::FromUTF8Err(e)
    }
}

impl From<bech32::Error> for Error {
    fn from(e: bech32::Error) -> Error {
        Error::Bech32Err(e)
    }
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Error {
        Error::SignatureError(e)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// vec u8 to vec u5
    fn eight2five(input: &Vec<u8>) -> Vec<U5> {
        let mut buffer = 0u64;
        let mut output = Vec::<U5>::new();
        let mut count = 0u64;
        for b in input {
            buffer = (buffer << 8) | (*b as u64 & 0xff);
            count += 8;
            while count >= 5 {
                output.push(((buffer >> (count - 5)) & 31) as u8);
                count -= 5
            }
        }
        output
    }

    /// vec u5 to vec u8
    fn five2eight(input: &Vec<U5>) -> Vec<u8> {
        let mut buffer = 0u64;
        let mut output = Vec::<U5>::new();
        let mut count = 0u64;
        for b in input {
            buffer = (buffer << 5) | (*b as u64 & 31);
            count += 5;
            while count >= 8 {
                output.push(((buffer >> (count - 8)) & 0xff) as u8);
                count -= 8
            }
        }
        assert!(count <= 4, "Zero-padding of more than 4 bits");
        assert_eq!(
            buffer & ((1 << count) - 1),
            0,
            "Non-zero padding in 8-to-5 conversion"
        );

        output
    }

    #[test]
    fn u5_test() {
        let u5_vec = vec![
            14, 20, 15, 7, 13, 26, 0, 25, 18, 6, 11, 13, 8, 21, 4, 20, 3, 17, 2, 29, 3, 12, 29, 3,
            4, 15, 24, 20, 6, 14, 30, 22,
        ];
        let u8_vec = vec![
            117, 30, 118, 232, 25, 145, 150, 212, 84, 148, 28, 69, 209, 179, 163, 35, 241, 67, 59,
            214,
        ];

        assert!(u5_vec.to_u8_vec(false).unwrap().eq(&u8_vec));
        assert!(u8_vec.to_u5_vec(true).unwrap().eq(&u5_vec));
        assert!(eight2five(&u8_vec).eq(&u5_vec));
        assert!(five2eight(&u5_vec).eq(&u8_vec));
    }
}
