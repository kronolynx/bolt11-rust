use std::num::ParseFloatError;
use std::{error, fmt};
use std::collections::HashMap;
use utils::*;

/// BOLT #11:
/// The following **multiplier** letters are defined:
///
/// 'm' (milli): multiply by 0.001
/// 'u' (micro): multiply by 0.000001
/// 'n' (nano): multiply by 0.000000001
/// 'p' (pico): multiply by 0.000000000001
///
struct Unit;

impl Unit {
    //    let units = ["p", "n", "u", "m"];
    fn value(c: char) -> f64 {
        match c {
            'p' => 1000_000_000_000f64,
            'n' => 1000_000_000f64,
            'u' => 1000_000f64,
            'm' => 1000f64,
            _ => 1f64,
        }
    }
    fn units<'a>() -> &'a [&'a str] {
        &["p", "n", "u", "m"]
    }
}

/// Given an amount in bitcoin, shorten it
///
/// BOLT #11:
/// A writer MUST encode `amount` as a positive decimal integer with no
/// leading zeroes, SHOULD use the shortest representation possible.
pub fn encode_amount(amount: f64) -> String {
    let units = Unit::units();
    // convert to pico initially
    let pico_amount = (amount * Unit::value('p')) as u64;
    encode_amount_aux(pico_amount, &units)
}

fn encode_amount_aux(amount: u64, units: &[&str]) -> String {
    if units.len() == 0 {
        amount.to_string()
    } else if amount % 1000 == 0 {
        encode_amount_aux(amount / 1000, &units[1..])
    } else {
        amount.to_string() + units[0]
    }
}

/// Given an encoded amount, convert it into a decimal
/// BOLT #11:
/// A reader SHOULD fail if `amount` contains a non-digit, or is followed by
/// anything except a `multiplier` in the table above.
/// # Arguments
/// * `amount` - A string that holds the amount to shorten
pub fn decode_amount(amount: &str) -> Result<f64, ParseFloatError> {
    let unit_char = amount.chars().last().map(|c| Unit::value(c));

    match unit_char {
        Some(u) if u != 1f64 => amount[..amount.len() - 1].parse::<f64>().map(|v| v / u),
        _ => amount.parse::<f64>(),
    }
}

#[test]
fn shorten_amount_test() {
    let test: HashMap<&str, f64> = hashmap!(
        "10p" => 10f64 / Unit::value('p'),
        "1n" => 1000f64 / Unit::value('p'),
        "1200p" => 1200f64 / Unit::value('p'),
        "123u" => 123f64 / Unit::value('u'),
        "123m" => 123f64 / 1000f64,
        "3" => 3f64
    );

    for (k, v) in test {
        assert_eq!(k, encode_amount(v));
        assert_eq!(v, decode_amount(&encode_amount(v)).unwrap());
    }
}

type ConvertResult = Result<Vec<u8>, BitConversionError>;

/// Convert between bit sizes
///
/// # Panics
/// Function will panic if attempting to convert `from` or `to` a bit size that
/// is larger than 8 bits.
fn convert_bits(data: &Vec<u8>, from: u32, to: u32, pad: bool) -> ConvertResult {
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
            return Err(BitConversionError::InvalidInputValue(v as u8));
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
        return Err(BitConversionError::InvalidPadding);
    }
    Ok(ret)
}

/// Convert a vector containing u5 values to u8
fn bits_u5_to_u8(bytes: &Vec<u8>) -> ConvertResult {
    convert_bits(bytes, 5, 8, false)
}
/// Convert a vector containing u8 values to u5
fn bits_u8_to_u5(bytes: &Vec<u8>) -> ConvertResult {
    convert_bits(bytes, 8, 5, false)
}

#[test]
fn u5_test() {
    let u5_vec = vec![14, 20, 15, 7, 13, 26, 0, 25, 18, 6, 11, 13, 8, 21, 4, 20, 3, 17, 2, 29, 3, 12, 29, 3, 4, 15, 24, 20, 6, 14, 30, 22];
    let u8_vec = vec![117, 30, 118, 232, 25, 145, 150, 212, 84, 148, 28, 69, 209, 179, 163, 35, 241, 67, 59, 214];

    assert!(bits_u5_to_u8(&u5_vec).unwrap().eq(&u8_vec));
    assert!(bits_u8_to_u5(&u8_vec).unwrap().eq(&u5_vec))
}

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

