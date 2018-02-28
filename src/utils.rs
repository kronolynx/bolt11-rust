//! utils

use std::fmt::Write;
use std::num;
use types::{ConvertResult, Error};
use std::ops::Range;

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
///
/// # Panics
/// Function will panic if attempting to convert `from` or `to` a bit size that
/// is larger than 8 bits.
pub fn convert_bits(data: &Vec<u8>, from: u32, to: u32, pad: bool) -> ConvertResult {
    if from > 8 || to > 8 {
        panic!("convert_bits `from` and `to` parameters greater than 8");
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
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return Err(Error::InvalidPadding);
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
}
