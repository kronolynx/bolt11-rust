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
