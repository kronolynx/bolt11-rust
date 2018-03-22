extern crate bolt11;

use bolt11::payment_request::PaymentRequest;

#[test]
fn decode_payment() {
    // more test in payment_request file
    let tx_ref = "lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2\
    ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq8rkx3yf5tcsyz3d73gafnh3cax9rn449d9p5uxz9ezhhypd0elx87sjle52x86fux2ypatgddc6k63n7erqz25le42c4u4ecky03ylcqca784w";

    let payment_request = PaymentRequest::decode(tx_ref).unwrap();

    let description = "Please consider supporting this project".to_string();

    assert_eq!(payment_request.prefix, "lnbc".to_string());
    assert_eq!(payment_request.description(), Some(description));
    assert_eq!(payment_request.timestamp, 1496_314_658u64);
    assert_eq!(payment_request.encode().unwrap(), tx_ref);
}