use bech32::{Bech32, create_checksum as bech32_checksum, CHARSET};
use tag::Tag;
use timestamp::Timestamp;
use types::{Error, U5, U5Conversions, U8Conversions};
use secp256k1;
use secp256k1::{Message, PublicKey, SecretKey, Signature};
use crypto::sha2::Sha256;
use crypto::digest::Digest;
use amount::Amount;
use std::fmt;
use base58check::*;
use itertools::Itertools;
use bitcoin_bech32::WitnessProgram;
use bitcoin_bech32::constants::Network;

/// Lightning Payment Request
/// * see https://github.com/lightningnetwork/lightning-rfc/blob/master/11-payment-encoding.md
#[derive(Debug, Clone)]
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
    // recovery id
    recovery_id: u8,
    // message
    message: Message,
}

impl PaymentRequest {
    pub fn read(input: &str) -> Result<PaymentRequest, Error> {
        let Bech32 { hrp, data } = Bech32::from_string(input.to_owned())?;

        let mut bytes = data.to_u8_vec()?;
        match bytes.len() {
            len if len >= 65 * 8 => Err(Error::InvalidLength(
                "data is too short to contain a 65 bytes signature".to_owned(),
            )),
            len => {
                let recovery_id = secp256k1::RecoveryId::parse(bytes[len - 1])?;
                bytes.remove(len - 1);

                let signature = PaymentRequest::parse_signature(&bytes.split_off(len - 65));

                let mut data = bytes.to_u5_vec()?;

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
                        recovery_id: recovery_id.serialize(),
                        message,
                    })
                } else {
                    Err(Error::SignatureError(secp256k1::Error::InvalidSignature))
                }
            }
        }
    }

    /// the payment hash
    pub fn payment_hash(&self) -> Option<Vec<u8>> {
        self.tags
            .iter()
            .filter_map(|v| match *v {
                Tag::PaymentHash { ref hash } => Some(hash.to_owned()),
                _ => None,
            })
            .next()
    }

    /// the description of the payment or its hash
    pub fn description(&self) -> Option<Description> {
        self.tags
            .iter()
            .filter_map(|v| match *v {
                Tag::Description { .. } | Tag::DescriptionHash { .. } => Description::new(v),
                _ => None,
            })
            .next()
    }

    /// the fallback address if any. It could be a script address, pubkey address, ..
    pub fn fallback_address(&self) -> Option<String> {
        // encode fallback address
        fn bech_address(version: u8, program: Vec<u8>, network: Network) -> Option<String> {
            let witness_program = WitnessProgram {
                version,
                program,
                network,
            };
            witness_program.to_address().ok()
        }
        // prefix used in fallback closure
        let prefix = &self.prefix;

        let fallback = |tag: &Tag| -> Option<String> {
            match *tag {
                Tag::FallbackAddress {
                    version: 17,
                    ref hash,
                } if prefix == "lnbc" =>
                {
                    // 0 PubkeyAddress
                    Some(hash.to_base58check(0))
                }
                Tag::FallbackAddress {
                    version: 18,
                    ref hash,
                } if prefix == "lnbc" =>
                {
                    // 5 ScriptAddress
                    Some(hash.as_slice().to_base58check(5))
                }
                Tag::FallbackAddress {
                    version: 17,
                    ref hash,
                } if prefix == "lntb" =>
                {
                    // 111 PubkeyAddressTestnet
                    Some(hash.as_slice().to_base58check(111))
                }
                Tag::FallbackAddress {
                    version: 18,
                    ref hash,
                } if prefix == "lntb" =>
                {
                    // 196 ScriptAddressTestnet
                    Some(hash.as_slice().to_base58check(196))
                }
                Tag::FallbackAddress { version, ref hash } if prefix == "lnbc" => {
                    bech_address(version, hash.to_owned(), Network::Bitcoin)
                }
                Tag::FallbackAddress { version, ref hash } if prefix == "lntb" => {
                    bech_address(version, hash.to_owned(), Network::Testnet)
                }
                _ => None,
            }
        };

        self.tags.iter().filter_map(fallback).next()
    }

    /// a representation of this payment request, without its signature, as a bit stream. This is what will be signed
    pub fn stream(&self) -> Result<Vec<u8>, Error> {
        let bytes = self.tags
            .iter()
            .flat_map(|tag| tag.to_vec_u5())
            .collect_vec()
            .concat();
        let bytes = [Timestamp::encode(self.timestamp), bytes].concat();

        bytes.to_u8_vec()
    }

    /// the hash of this payment request
    pub fn hash(&self) -> Result<Vec<u8>, Error> {
        let amount = self.amount
            .map_or(String::new(), |a| Amount::encode(a as f64));
        let bytes = (self.prefix.to_owned() + &amount).as_bytes().to_vec();
        self.stream()
            .map(|s| PaymentRequest::sha256_hasher(&[bytes, s].concat()).to_vec())
    }

    /// encode to bech32 payment request
    pub fn write(&self) -> Result<String, Error> {
        let hr_amount = self.amount
            .map_or(String::new(), |a| Amount::encode(a as f64));
        let mut hrp = self.prefix.to_owned() + &hr_amount;
        let stream = [
            self.stream()?,
            self.signature.serialize().to_vec(),
            vec![self.recovery_id],
        ].concat();
        let u5_stream = stream.to_u5_vec()?;
        let checksum = bech32_checksum(&hrp.as_bytes().to_vec(), &u5_stream);

        let stream_sum = [u5_stream, checksum]
            .concat()
            .iter()
            .map(|i| CHARSET[*i as usize])
            .collect::<String>();
        hrp.push_str("1");
        hrp.push_str(&stream_sum);
        Ok(hrp)
    }

    /// sign a payment request
    pub fn sign(&self, secret_key: &SecretKey) -> Result<PaymentRequest, Error> {
        match secp256k1::sign(&self.message, secret_key) {
            Ok((signature, recovery_id)) => {
                let mut signed = self.clone();
                signed.signature = signature;
                Ok(signed)
            }
            Err(e) => Err(Error::SignatureError(e)),
        }
    }

    // parse the message
    fn parse_message(hrp: &String, bytes: &Vec<u8>) -> Message {
        let message_bytes = [hrp.as_bytes(), bytes.as_slice()].concat();
        let raw_message = PaymentRequest::sha256_hasher(&message_bytes);

        secp256k1::Message::parse(&raw_message)
    }

    fn sha256_hasher(bytes: &Vec<u8>) -> [u8; 32] {
        let mut hash = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.input(bytes);
        hasher.result(&mut hash);
        hash
    }

    // parse the signature
    fn parse_signature(bytes: &Vec<u8>) -> Signature {
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

/// PaymentRequest description
pub enum Description {
    Tag(String),
    HashTag(Vec<u8>),
}

impl Description {
    /// Retrieve the description from the tag
    pub fn new(tag: &Tag) -> Option<Description> {
        match *tag {
            Tag::Description { ref description } => Some(Description::Tag(description.to_owned())),
            Tag::DescriptionHash { ref hash } => Some(Description::HashTag(hash.to_owned())),
            _ => None,
        }
    }
}

impl fmt::Display for Description {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Description::Tag(ref description) => write!(f, "{}", description),
            Description::HashTag(ref hash) => write!(f, "{}", ::utils::to_hex(&hash)),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use lazy_static;
    use utils::from_hex;

    lazy_static!{
         static ref SEC_KEY: secp256k1::SecretKey = {
            let key = from_hex(
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
         static ref PUB_KEY: secp256k1::PublicKey = secp256k1::PublicKey::from_secret_key(&SEC_KEY);
    }

    #[test]
    fn read() {
        let tx_ref = "lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2p\
        kx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq8rkx3yf5tcsyz3d73gafnh3cax9r\
        n449d9p5uxz9ezhhypd0elx87sjle52x86fux2ypatgddc6k63n7erqz25le42c4u4ecky03ylcqca784w";

        let pay_request = PaymentRequest::read(&tx_ref).unwrap();

        let payment_hash =
            from_hex("0001020304050607080900010203040506070809000102030405060708090102").unwrap();

        assert_eq!(pay_request.prefix, "lnbc");
        assert!(pay_request.amount.is_none());
        assert_eq!(pay_request.payment_hash().unwrap(), payment_hash);
        assert_eq!(pay_request.timestamp, 1496314658u64);
        assert_eq!(
            pay_request.description().unwrap().to_string(),
            "Please consider supporting this project".to_owned()
        );
        assert_eq!(pay_request.fallback_address(), None);
        assert_eq!(pay_request.tags.len(), 2);
        assert_eq!(pay_request.write().unwrap(), tx_ref);
        assert_eq!(pay_request.sign(&SEC_KEY).unwrap().write().unwrap(), tx_ref);
    }
}
