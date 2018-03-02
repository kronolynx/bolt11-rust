use bech32::Bech32;
use tag::Tag;
use timestamp::Timestamp;
use types::{Error, VecU5};
use secp256k1;
use secp256k1::{Message, PublicKey, Signature};
use crypto::sha2::Sha256;
use crypto::digest::Digest;
use amount::Amount;

/// Lightning Payment Request
/// * see https://github.com/lightningnetwork/lightning-rfc/blob/master/11-payment-encoding.md
#[derive(Debug)]
pub struct PaymentRequest {
    /// currency prefix; lnbc for bitcoin, lntb for bitcoin testnet
    pub prefix: String,
    /// amount to pay (empty string means no amount is specified)
    pub amount: Option<u64>,
    /// request timestamp (UNIX format)
    pub timestamp: u64,
    /// id of the node emitting the payment request
    pub node_id: PublicKey,
    /// payment tags; must include a single PaymentHash tag
    pub tags: Vec<Tag>,
    /// request signature that will be checked against node id
    pub signature: Signature,
}

impl PaymentRequest {
    pub fn read(input: &str) -> Result<PaymentRequest, Error> {
        let Bech32 { hrp, data } = Bech32::from_string(input.to_owned())?;

        let mut bytes = VecU5::to_u8_vec(&data)?;
        match bytes.len() {
            len if len >= 65 * 8 => Err(Error::InvalidLength(
                "data is too short to contain a 65 bytes signature".to_owned(),
            )),
            len => {
                let recovery_id = secp256k1::RecoveryId::parse(bytes[len - 1])?;
                bytes.remove(len - 1);

                let signature = PaymentRequest::parse_signature(bytes.split_off(len - 65));

                let mut data = VecU5::from_u8_vec(&bytes)?;

                let timestamp = Timestamp::decode(&data.drain(..7).collect::<Vec<_>>());
                let tags = Tag::parse_all(&data)?;
                let message = PaymentRequest::parse_message(&hrp, &bytes);
                // public key
                let node_id = secp256k1::recover(&message, &signature, &recovery_id)?;

                let prefix = hrp[..4].to_owned();
                let amount = hrp.get(4..)
                    .and_then(|u| Amount::decode(u).ok())
                    .map(|u| u as u64);
                let valid_signature = secp256k1::verify(&message, &signature, &node_id);
                if valid_signature {
                    Ok(PaymentRequest {
                        prefix,
                        amount,
                        timestamp,
                        node_id,
                        tags,
                        signature,
                    })
                } else {
                    Err(Error::SignatureError(secp256k1::Error::InvalidSignature))
                }
            }
        }
    }

    // parse the message
    fn parse_message(hrp: &String, bytes: &Vec<u8>) -> Message {
        let mut raw_message = [0u8; 32];
        let message_bytes = [hrp.as_bytes(), bytes.as_slice()].concat();
        let mut hasher = Sha256::new();
        hasher.input(&message_bytes);
        hasher.result(&mut raw_message);

        secp256k1::Message::parse(&raw_message)
    }

    // parse the signature
    fn parse_signature(bytes: Vec<u8>) -> Signature {
        let sig_raw = bytes
            .iter()
            .enumerate()
            .fold([0u8; 64], |mut acc, (index, item)| {
                acc[index] = *item;
                acc
            });

        secp256k1::Signature::parse(&sig_raw)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use lazy_static;

    lazy_static!{
         static ref SEC_KEY : secp256k1::SecretKey = {
            let key = ::utils::from_hex(
                "e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734",
            ).unwrap()
                .iter()
                .enumerate()
                .fold([0u8; 32], |mut acc, (index, item)| {
                    acc[index] = *item;
                    acc
                });
            secp256k1::SecretKey::parse(&key).unwrap()
         };
         static ref PUB_KEY : secp256k1::PublicKey = secp256k1::PublicKey::from_secret_key(&SEC_KEY);
    }

    #[test]
    fn read() {
        let tx_ref = "lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2p\
        kx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq8rkx3yf5tcsyz3d73gafnh3cax9r\
        n449d9p5uxz9ezhhypd0elx87sjle52x86fux2ypatgddc6k63n7erqz25le42c4u4ecky03ylcqca784w";

        let pay_request = PaymentRequest::read(&tx_ref).unwrap();
        assert!(pay_request.prefix == "lnbc");
        assert!(pay_request.amount.is_none());
    }
}
