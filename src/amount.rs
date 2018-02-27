use types::Error;
/// Bitcoin subunits
/// The following **multiplier** letters are defined:
///
/// 'm' (milli): multiply by 0.001
/// 'u' (micro): multiply by 0.000001
/// 'n' (nano): multiply by 0.000000001
/// 'p' (pico): multiply by 0.000000000001
///
pub struct Amount;

impl Amount {
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

    /// Given an amount in Bitcoin, shorten it
    ///
    /// BOLT #11:
    /// A writer MUST encode `amount` as a positive decimal integer with no
    /// leading zeroes, SHOULD use the shortest representation possible.
    pub fn encode(amount: f64) -> String {
        // encode amount aux helper
        fn aux(amount: u64, units: &[&str]) -> String {
            if units.len() == 0 {
                amount.to_string()
            } else if amount % 1000 == 0 {
                aux(amount / 1000, &units[1..])
            } else {
                amount.to_string() + units[0]
            }
        }

        let units = Amount::units();
        // convert to pico initially
        let pico_amount = (amount * Amount::value('p')) as u64;
        aux(pico_amount, &units)
    }

    /// Given an encoded amount, convert it into a decimal
    /// BOLT #11:
    /// A reader SHOULD fail if `amount` contains a non-digit, or is followed by
    /// anything except a `multiplier` in the table above.
    /// # Arguments
    /// * `amount` - A string that holds the amount to shorten
    pub fn decode(amount: &str) -> Result<f64, Error> {
        let unit_char = amount.chars().last().map(|c| Amount::value(c));

        match unit_char {
            Some(u) if u != 1f64 => amount[..amount.len() - 1].parse::<f64>().map(|v| v / u),
            _ => amount.parse::<f64>(),
        }.map_err(Error::ParseFloatErr)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn encode_decode_amount() {
        let test: HashMap<&str, f64> = hashmap!(
        "10p" => 10f64 / Amount::value('p'),
        "1n" => 1000f64 / Amount::value('p'),
        "1200p" => 1200f64 / Amount::value('p'),
        "123u" => 123f64 / Amount::value('u'),
        "123m" => 123f64 / 1000f64,
        "3" => 3f64
    );

        for (k, v) in test {
            assert_eq!(k, Amount::encode(v));
            assert_eq!(v, Amount::decode(&Amount::encode(v)).unwrap());
        }
    }
}
