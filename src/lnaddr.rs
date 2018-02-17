use std::num::ParseFloatError;
use std::collections::HashMap;
use types::{BitConversionError, ConvertResult, U5, VecU5, VecU8};
use bech32::Bech32;

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
/// Payment Hash Tag
///
/// # Arguments
/// * `hash` payment hash
struct PaymentHashTag {
    hash: Vec<u8>,
}

/// Description Tag
/// # Arguments
/// * `description` a free-format string that will be included in the payment request
struct DescriptionTag {
    description: String,
}

/// Hash Tag
/// # Arguments
/// `hash` hash that will be included in the payment request, and can be checked against
///  the hash of a long description, an invoice, ...
struct DescriptionHashTag {
    hash: Vec<u8>,
}
/// Tag
pub enum Tag {
    PaymentHashTag,
    DescriptionTag,
    DescriptionHashTag,
}

/// Trait for types that convert to Vec<U5>
trait ToVecU5 {
    fn to_vec_u5(&self) -> Result<Vec<U5>, String>;
    // auxiliary method for to_vec_u5
    fn to_vec_u5_result(
        ch_value: Option<usize>,
        bytes_result: Result<Vec<U5>, BitConversionError>,
    ) -> Result<Vec<U5>, String> {
        match (ch_value, bytes_result) {
            (Some(p), Ok(bytes)) => {
                let len = bytes.len();
                let mut vec = vec![p as u8, (len / 32) as u8, (len % 32) as u8];
                vec.extend(bytes);
                Ok(vec)
            }
            (_, Err(err)) => Err(err.to_string()),
            _ => Err("Invalid input".to_owned()),
        }
    }
}

impl ToVecU5 for PaymentHashTag {
    fn to_vec_u5(&self) -> Result<Vec<U5>, String> {
        let bytes: Result<Vec<U5>, BitConversionError> = VecU8::to_u5(&self.hash);
        println!("bytes \n{:?}", bytes);
        let p = Bech32Extra::ALPHABET.find('p');
        PaymentHashTag::to_vec_u5_result(p, bytes)
    }
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

/// Things related to bech32
struct Bech32Extra;

impl Bech32Extra {
    const ALPHABET: &'static str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn payment_hashtag_test() {
        let payment_hash_tag = PaymentHashTag {
            hash: vec![
                0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6,
                7, 8, 9, 1, 2,
            ],
        };
        let u5_hash_tag = vec![
            1u8, 1, 20, 0, 0, 0, 16, 4, 0, 24, 4, 0, 20, 3, 0, 14, 2, 0, 9, 0, 0, 0, 16, 4, 0, 24,
            4, 0, 20, 3, 0, 14, 2, 0, 9, 0, 0, 0, 16, 4, 0, 24, 4, 0, 20, 3, 0, 14, 2, 0, 9, 0, 4,
            1, 0,
        ];
        println!("hashtag {:?}", payment_hash_tag.to_vec_u5().unwrap());
        println!("right   {:?}", u5_hash_tag);
        assert!(payment_hash_tag.to_vec_u5().unwrap().eq(&u5_hash_tag))
    }

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
    fn timestamp_test() {
        let data: Vec<U5> = vec![1, 12, 18, 31, 28, 25, 2];
        let timestamp = 1496314658;

        assert_eq!(Timestamp::decode(&data), timestamp);
        assert!(data.eq(&Timestamp::encode(timestamp)));
    }
}
