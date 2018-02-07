use std::collections::HashMap;
use num::traits::*;
use num::bigint::BigUint;

/// Given an amount in bitcoin, shorten it
///
/// BOLT #11:
/// A writer MUST encode `amount` as a positive decimal integer with no
/// leading zeroes, SHOULD use the shortest representation possible.
pub fn shorten_amount(amount: f64) -> String {
    let units = ["p", "n", "u", "m"];
    // convert to pico initially
    let pico_amount = (amount * (10f64).powi(12)) as u64;
    shorten_amount_aux(pico_amount, &units)
}

fn shorten_amount_aux(amount: u64, units: &[&str]) -> String {
    if units.len() == 0 {
        amount.to_string()
    } else if amount % 1000 == 0 {
        shorten_amount_aux(amount / 1000, &units[1..])
    } else {
        amount.to_string() + units[0]
    }
}

/// Given a shortened amount, convert it into a decimal
/// BOLT #11:
/// The following `multiplier` letters are defined:
///
///* `m` (milli): multiply by 0.001
///* `u` (micro): multiply by 0.000001
///* `n` (nano): multiply by 0.000000001
///* `p` (pico): multiply by 0.000000000001
pub fn unshorten_amount(amount: String) -> f64 {
    let units: HashMap<char, i32> = hashmap! {
        'p' => 12,
        'n' => 9,
        'u' => 6,
        'm' => 3
    };

    let unit = amount
        .chars()
        .last()
        .and_then(|c| units.get(&c));

    match unit {
        Some(u) => {
            *&amount[..amount.len() - 1]
                .parse::<f64>()
                .map(|v| v / 10f64.powi(*u))
                .expect("Invalid amount")
        }
        _ => {
            *&amount
                .parse::<f64>()
                .expect("Invalid amount")
        }
    }
}

#[test]
fn shorten_amount_test() {
    let test: HashMap<&str, f64> = hashmap!(
        "10p" => 10f64 / (10f64.powi(12)),
        "1n" => 1000f64 / (10f64.powi(12)),
        "1200p" => 1200f64 / (10f64.powi(12)),
        "123u" => 123f64 / (10f64.powi(6)),
        "123m" => 123f64 / 1000f64,
        "3" => 3f64
    );

    for (k, v) in test {
        assert_eq!(k, shorten_amount(v));
        assert_eq!(v, unshorten_amount(shorten_amount(v)));
    }
}

/// Shim in a hexstring vectors of 5-bit values returned by BECH32
fn bitarray_to_u5(data: Vec<u8>) -> String {
    let u5 = data.iter()
        .fold(BigUint::from(0u64), |mut s, b| {
            s <<= 5;
            s |= BigUint::from(*b);
            s
        });
    u5.to_str_radix(16)
}

/// Convert hextring containing 5-bit values to u8 vector
fn u5_to_bitarray(hex: &str) -> Result<Vec<u8>, &str> {
    BigUint::parse_bytes(hex.as_bytes(), 16)
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
    let bytes = vec![3u8, 1, 17, 17, 8, 15, 0, 20, 24, 20, 11, 6, 16, 1, 5, 29, 3, 4, 16, 3, 6, 21, 22, 26, 2, 13, 22, 9, 16, 21, 19, 24, 25, 21, 6, 18, 15, 8, 13, 24, 24, 24, 25, 9, 12, 1, 4, 16, 6, 9, 17, 0];
    let hex = "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c63296049032620";
    assert_eq!(bitarray_to_u5(bytes), hex);
    assert_eq!(bitarray_to_u5(u5_to_bitarray(hex).unwrap()), hex);
}

