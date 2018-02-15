use std::num::ParseFloatError;
use std::collections::HashMap;
use utils::convert_bits;
use types::{ConvertResult, U5};

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

/// Convert a vector containing u5 values to u8
fn bits_u5_to_u8(bytes: &Vec<U5>) -> ConvertResult {
    convert_bits(bytes, 5, 8, false)
}
/// Convert a vector containing u8 values to u5
fn bits_u8_to_u5(bytes: &Vec<u8>) -> ConvertResult {
    convert_bits(bytes, 8, 5, false)
}

/// seconds-since-1970 (35 bits, big-endian)
struct Timestamp;

impl Timestamp {
    /// decode timestamp from u5 vector
    fn decode(data: &Vec<U5>) -> u64 {
        data.iter().take(7).fold(0, |a, b| a * 32u64 + *b as u64)
    }
    /// encode timestamp
    fn encode(timestamp: u64) -> Vec<U5> {
        let mut acc: Vec<U5> = Vec::new();
        let mut time_acc = timestamp;
        while acc.len() < 7 {
            acc.push((time_acc % 32) as U5);
            time_acc /= 32;
        }
        acc.reverse();
        acc
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn encode_decode_amount_test() {
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

        assert!(bits_u5_to_u8(&u5_vec).unwrap().eq(&u8_vec));
        assert!(bits_u8_to_u5(&u8_vec).unwrap().eq(&u5_vec))
    }

    #[test]
    fn timestamp_test() {
        let data: Vec<U5> = vec![1, 12, 18, 31, 28, 25, 2];
        let timestamp = 1496314658;

        assert_eq!(Timestamp::decode(&data), timestamp);
        assert!(data.eq(&Timestamp::encode(timestamp)));
    }
}
