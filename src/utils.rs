//! utils

use std::fmt::Write;
use std::num;
use types::{ConvertResult, Error};
use num::bigint::BigUint;

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
/// convert vec u8 to hex-string
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut acc: String, b: &u8| {
        write!(&mut acc, "{:02x}", b).expect("Unable to write");
        acc
    })
}

/// Decode a hex string into bytes.
pub fn from_hex(hex_str: &str) -> Result<Vec<u8>, num::ParseIntError> {
    let padded: String = if hex_str.len() % 2 != 0 {
        let mut s = String::from("0");
        s.push_str(hex_str);
        s
    } else {
        hex_str.to_owned()
    };
    split_n(&padded.trim()[..], 2)
        .iter()
        .map(|b| u8::from_str_radix(b, 16))
        .collect::<Result<Vec<u8>, _>>()
}
/// split a string in chunks, the length of the string must be even
fn split_n(s: &str, n: usize) -> Vec<&str> {
    (0..(s.len() - n + 1) / 2 + 1)
        .map(|i| &s[2 * i..2 * i + n])
        .collect()
}

/// Convert between bit sizes
pub fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> ConvertResult {
    if from > 8 || to > 8 {
        return Err(Error::InvalidParameter(
            "convert_bits `from` and `to` parameters greater than 8".to_owned(),
        ));
    }
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut ret: Vec<u8> = Vec::new();
    let maxv: u32 = (1 << to) - 1;
    for value in data {
        let v: u32 = *value as u32;
        if (v >> from) != 0 {
            // Input value exceeds `from` bit size
            return Err(Error::InvalidInputValue(v as u8));
        }
        acc = (acc << from) | v;
        bits += from;
        while bits >= to {
            bits -= to;
            ret.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            ret.push(((acc << (to - bits)) & maxv) as u8);
        }
    }
    Ok(ret)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_to_hex() {
        assert_eq!(to_hex(&vec![0, 0, 0, 0]), "00000000");
        assert_eq!(to_hex(&vec![10, 11, 12, 13]), "0a0b0c0d");
        assert_eq!(to_hex(&vec![0, 0, 0, 255]), "000000ff");
    }

    #[test]
    fn test_from_hex() {
        assert_eq!(from_hex("00000000").unwrap(), vec![0, 0, 0, 0]);
        assert_eq!(from_hex("0a0b0c0d").unwrap(), vec![10, 11, 12, 13]);
        assert_eq!(from_hex("000000ff").unwrap(), vec![0, 0, 0, 255]);
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
    }
}
