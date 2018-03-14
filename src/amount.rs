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
    /// the unit allowing for the shortest representation possible
    fn unit(amount: u64) -> char {
        match amount * 10 {
            pico if pico % 1000 > 0 => 'p',
            pico if pico % 1000_000 > 0 => 'n',
            pico if pico % 1000_000_000 > 0 => 'u',
            _ => 'm',
        }
    }

    /// Given an encoded amount, convert it into millisatoshis
    /// BOLT #11:
    /// A reader SHOULD fail if `amount` contains a non-digit, or is followed by
    /// anything except a `multiplier` in the table above.
    /// # Arguments
    /// * `amount` - A string that holds the amount to shorten
    pub fn decode(amount: &str) -> Result<u64, Error> {
        match amount.chars().last() {
            Some(a) if a == 'p' => amount[..amount.len() - 1].parse::<u64>().map(|v| v / 10),
            Some(a) if a == 'n' => amount[..amount.len() - 1].parse::<u64>().map(|v| v * 100),
            Some(a) if a == 'u' => amount[..amount.len() - 1]
                .parse::<u64>()
                .map(|v| v * 100_000),
            Some(a) if a == 'm' => amount[..amount.len() - 1]
                .parse::<u64>()
                .map(|v| v * 100_000_000),
            _ => amount.parse::<u64>(),
        }.map_err(Error::ParseIntErr)
    }

    /// Given an amount in Bitcoin, shorten it
    ///
    /// BOLT #11:
    /// A writer MUST encode `amount` as a positive decimal integer with no
    /// leading zeroes, SHOULD use the shortest representation possible.
    pub fn encode(amount: u64) -> String {
        match amount {
            amt if Amount::unit(amt) == 'p' => format!("{}p", amt * 10),
            amt if Amount::unit(amt) == 'n' => format!("{}n", amt / 100),
            amt if Amount::unit(amt) == 'u' => format!("{}u", amt / 100_000),
            amt if Amount::unit(amt) == 'm' => format!("{}m", amt / 100_000_000),
            amt => amt.to_string(),
        }
    }
}

pub enum BtcAmount {
    Btc(f64),
    MilliBtc(f64),
    Satoshi(u64),
    MilliSatoshi(u64),
}

impl BtcAmount {
    fn to_btc(&self) -> f64 {
        match *self {
            BtcAmount::Btc(a) => a,
            BtcAmount::MilliBtc(a) => a / 1000f64,
            BtcAmount::Satoshi(a) => unimplemented!(),
            BtcAmount::MilliSatoshi(a) => unimplemented!(),
        }
    }
    fn to_millisatoshi(&self) -> u64 {
        match *self {
            BtcAmount::Btc(a) => unimplemented!(),
            BtcAmount::MilliBtc(a) => unimplemented!(),
            BtcAmount::Satoshi(a) => unimplemented!(),
            BtcAmount::MilliSatoshi(a) => unimplemented!(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn minimal_amount_used() {
        assert_eq!(Some('p'), Amount::encode(1).chars().last());
        assert_eq!(Some('p'), Amount::encode(99).chars().last());
        assert_eq!(Some('n'), Amount::encode(100).chars().last());
        assert_eq!(Some('p'), Amount::encode(101).chars().last());

        assert_eq!(Some('n'), Amount::encode(1000).chars().last());
        assert_eq!(Some('u'), Amount::encode(100_000).chars().last());
        assert_eq!(Some('n'), Amount::encode(101_000).chars().last());
        assert_eq!(Some('u'), Amount::encode(1155_400_000).chars().last());

        assert_eq!(Some('m'), Amount::encode(100_000_000).chars().last());
        assert_eq!(Some('m'), Amount::encode(1000_000_000).chars().last());
        assert_eq!(Some('m'), Amount::encode(100_000_000_000).chars().last());
    }
    #[test]
    fn decode() {
        assert_eq!(100_000_000u64, Amount::decode("1m").unwrap());
        assert_eq!(100_000_000u64, Amount::decode("1000u").unwrap());
        assert_eq!(100_000_000u64, Amount::decode("1000000n").unwrap());
        assert_eq!(100_000_000u64, Amount::decode("1000000000p").unwrap());
    }
}
