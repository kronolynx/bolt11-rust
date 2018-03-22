# Lightning Payments Requests (BOLT #11) Implementation


This is an implementation of [Lightning BOLT11 Specification](https://github.com/lightningnetwork/lightning-rfc/blob/master/11-payment-encoding.md) for providing a minimal QR-code-ready format for requesting
lightning payments.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
bolt11 = "0.1.0"
```

and this to your crate root:

```rust
extern crate bolt11;
```

## Example

```rust
use bolt11::payment_request::PaymentRequest;

let encoded_payment_request = "lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqf
    qqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpuaztrnwngzn3kdzw5hydlzf03qdgm2hdq
    27cqv3agm2awhz5se903vruatfhq77w3ls4evs3ch9zw97j25emudupq63nyw24cg27h2rspfj9srp";

let payment_request = PaymentRequest::decode(encoded_payment_request);

```
