use std::collections::HashMap;

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
    let mut units = HashMap::new();
    units.insert('p', 12);
    units.insert('n', 9);
    units.insert('u', 6);
    units.insert('m', 3);

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
    let mut test = HashMap::new();
    test.insert("10p", 10f64 / (10f64.powi(12)));
    test.insert("1n", 1000f64 / (10f64.powi(12)));
    test.insert("1200p", 1200f64 / (10f64.powi(12)));
    test.insert("123u", 123f64 / (10f64.powi(6)));
    test.insert("123m", 123f64 / 1000f64);
    test.insert("3", 3f64);

    for (k, v) in test {
        assert_eq!(k, shorten_amount(v));
        assert_eq!(v, unshorten_amount(shorten_amount(v)));
    }
}
