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
    }
}
