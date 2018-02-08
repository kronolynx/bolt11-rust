use std::collections::HashMap;
use num::traits::*;
use num::bigint::BigUint;
use std::num::ParseFloatError;

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

/// Shim in a hex string vectors of 5-bit values returned by BECH32
///
/// # Arguments
/// * `bitarray` - Vector that hold the 5-bit values
fn bitarray_to_u5(bitarray: Vec<u8>) -> String {
    let u5 = bitarray.iter().fold(BigUint::from(0u64), |mut s, b| {
        s <<= 5;
        s |= BigUint::from(*b);
        s
    });
    u5.to_str_radix(16)
}

/// Convert hex tring containing 5-bit values to u8 vector
///
/// # Arguments
/// * `hex_string` - Hex string that contains the 5-bit values
fn u5_to_bitarray(hex_string: &str) -> Result<Vec<u8>, &str> {
    BigUint::parse_bytes(hex_string.as_bytes(), 16)
        .ok_or("Error parsing hexstring")
        .and_then(|mut u5| {
            let mask = BigUint::from(31u8);
            let mut bitarray = Vec::<u8>::new();
            while !u5.is_zero() {
                let bit = &u5 & &mask;
                if let Some(b) = bit.to_u8() {
                    bitarray.push(b);
                } else {
                    return Err("Invalid u5");
                }
                u5 >>= 5;
            }
            bitarray.reverse();
            Ok(bitarray)
        })
}

#[test]
fn u5_test() {
    let bytes = vec![
        3u8, 1, 17, 17, 8, 15, 0, 20, 24, 20, 11, 6, 16, 1, 5, 29, 3, 4, 16, 3, 6, 21, 22, 26, 2,
        13, 22, 9, 16, 21, 19, 24, 25, 21, 6, 18, 15, 8, 13, 24, 24, 24, 25, 9, 12, 1, 4, 16, 6, 9,
        17, 0,
    ];
    let hex = "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c63296049032620";
    assert_eq!(bitarray_to_u5(bytes), hex);
    assert_eq!(bitarray_to_u5(u5_to_bitarray(hex).unwrap()), hex);
}
