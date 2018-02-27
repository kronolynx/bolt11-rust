use std::collections::HashMap;
use types::{Error, U5};
use num::bigint::{BigInt, Sign};

/// Bitcoin subunits
/// The following **multiplier** letters are defined:
///
/// 'm' (milli): multiply by 0.001
/// 'u' (micro): multiply by 0.000001
/// 'n' (nano): multiply by 0.000000001
/// 'p' (pico): multiply by 0.000000000001
///
pub struct Unit;

impl Unit {
    /// value corresponding to a given letter
    pub fn value(c: char) -> f64 {
        match c {
            'p' => 1000_000_000_000f64,
            'n' => 1000_000_000f64,
            'u' => 1000_000f64,
            'm' => 1000f64,
            _ => 1f64,
        }
    }
    /// multiplier letters
    pub fn units<'a>() -> &'a [&'a str] {
        &["p", "n", "u", "m"]
    }
}

/// BOLT #11:

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
pub fn decode_amount(amount: &str) -> Result<f64, Error> {
    let unit_char = amount.chars().last().map(|c| Unit::value(c));

    match unit_char {
        Some(u) if u != 1f64 => amount[..amount.len() - 1].parse::<f64>().map(|v| v / u),
        _ => amount.parse::<f64>(),
    }.map_err(Error::ParseFloatErr)
}

/// bitcoin-style signature of above (520 bits)
struct Signature {
    /// r (32 bytes)
    r: BigInt,
    /// s (32 bytes)
    s: BigInt,
    /// recovery id (1 byte)
    recovery_id: u8,
}

impl Signature {
    /// decode signature
    pub fn decode(signature: &Vec<u8>) -> Result<Signature, Error> {
        match signature.len() {
            len if len < 65 => Err(Error::InvalidLength(
                "Incorrect signature length".to_owned(),
            )),
            _ => {
                let r = BigInt::from_bytes_be(Sign::Plus, &signature[..32]);
                let s = BigInt::from_bytes_be(Sign::Plus, &signature[32..64]);
                let recovery_id = signature[64];
                Ok(Signature { r, s, recovery_id })
            }
        }
    }
    /// encode signature
    pub fn encode(&self) -> Vec<u8> {
        fn fix_size(bytes: Vec<u8>) -> Vec<u8> {
            match bytes.len() {
                32 => bytes,
                len if len < 32 => [vec![0; 32 - len], bytes].concat(),
                len => bytes[len - 32..].to_vec(),
            }
        }

        let r = fix_size(self.r.to_bytes_be().1);
        let s = fix_size(self.s.to_bytes_be().1);

        [r, s, vec![self.recovery_id]].concat()
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
        // 35 bits, big-endian
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
    fn encode_decode_amount() {
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
    fn timestamp() {
        let data: Vec<U5> = vec![1, 12, 18, 31, 28, 25, 2];
        let timestamp = 1496314658;

        assert_eq!(Timestamp::decode(&data), timestamp);
        assert!(data.eq(&Timestamp::encode(timestamp)));
    }

    #[test]
    fn signature() {
        let hex_str = "38ec6891345e204145be8a3a99de38e98a39d6a569434e1845c8af7205afcfcc7f425\
                       fcd1463e93c32881ead0d6e356d467ec8c02553f9aab15e5738b11f127f00";
        let Signature { r, s, recovery_id } =
            Signature::decode(&::utils::from_hex(&hex_str).unwrap()).unwrap();
        let bytes = Signature { r, s, recovery_id }.encode();
        assert_eq!(::utils::to_hex(&bytes), hex_str)
    }
}
