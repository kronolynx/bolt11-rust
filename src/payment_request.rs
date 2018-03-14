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
    /// amount to pay in millisatoshis (empty string means no amount is specified)
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
    pub fn decode(input: &str) -> Result<PaymentRequest, Error> {
        let Bech32 { hrp, mut data } = Bech32::from_string(input.to_owned())?;

        match data.len() {
            // 65 bytes signature length (65 + 7) * 8 / 5 = 104
            len if len < 116 => Err(Error::InvalidLength(
                "data is too short to decode".to_owned(),
            )),
            len => {
                let (recovery_id, signature) = {
                    let signature_bytes = data.split_off(len - 104).to_u8_vec(false)?;
                    // last byte of the signature
                    let recovery_id = secp256k1::RecoveryId::parse(signature_bytes[65 - 1])?;
                    let signature = PaymentRequest::parse_signature(&signature_bytes[..65 - 1]);
                    (recovery_id, signature)
                };

                let message = PaymentRequest::parse_message(&hrp, &data.to_u8_vec(false)?);
                let timestamp = Timestamp::decode(&data.drain(..7).collect::<Vec<_>>());
                let tags = Tag::parse_all(&data)?;

                let node_id = secp256k1::recover(&message, &signature, &recovery_id)?;

                let prefix = hrp[..4].to_owned();
                let amount = hrp.get(4..).and_then(|u| Amount::decode(u).ok());
                //                    .map(|u| u as u64);
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

        bytes.to_u8_vec(false)
    }

    /// the hash of this payment request
    pub fn hash(&self) -> Result<Vec<u8>, Error> {
        let amount = self.amount.map_or(String::new(), |a| Amount::encode(a));
        let bytes = (self.prefix.to_owned() + &amount).as_bytes().to_vec();
        self.stream()
            .map(|s| PaymentRequest::sha256_hasher(&[bytes, s].concat()).to_vec())
    }

    /// encode to bech32 payment request
    pub fn encode(&self) -> Result<String, Error> {
        let hr_amount = self.amount.map_or(String::new(), |a| Amount::encode(a));
        let mut hrp = self.prefix.to_owned() + &hr_amount;
        let stream = [
            self.stream()?,
            self.signature.serialize().to_vec(),
            vec![self.recovery_id],
        ].concat();
        let u5_stream = stream.to_u5_vec(true)?;
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
    fn parse_signature(bytes: &[u8]) -> Signature {
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
    fn test0() {
        let tx_ref = "lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2p\
        kx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq8rkx3yf5tcsyz3d73gafnh3cax9r\
        n449d9p5uxz9ezhhypd0elx87sjle52x86fux2ypatgddc6k63n7erqz25le42c4u4ecky03ylcqca784w";

        let pay_request = PaymentRequest::decode(&tx_ref).unwrap();

        let payment_hash =
            from_hex("0001020304050607080900010203040506070809000102030405060708090102").unwrap();

        assert_eq!(pay_request.prefix, "lnbc");
        assert!(pay_request.amount.is_none());
        assert_eq!(pay_request.payment_hash().unwrap(), payment_hash);
        assert_eq!(pay_request.timestamp, 1496_314_658u64);
        assert_eq!(
            pay_request.description().unwrap().to_string(),
            "Please consider supporting this project".to_owned()
        );
        assert_eq!(pay_request.fallback_address(), None);
        assert_eq!(pay_request.tags.len(), 2);
        assert_eq!(pay_request.encode().unwrap(), tx_ref);
        assert_eq!(
            pay_request.sign(&SEC_KEY).unwrap().encode().unwrap(),
            tx_ref
        );
    }

    #[test]
    fn test1() {
        let tx_ref = "lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqd\
        q5xysxxatsyp3k7enxv4jsxqzpuaztrnwngzn3kdzw5hydlzf03qdgm2hdq27cqv3agm2awhz5se903vruatfhq77w\
        3ls4evs3ch9zw97j25emudupq63nyw24cg27h2rspfj9srp";
        let pay_request = PaymentRequest::decode(&tx_ref).unwrap();
        let payment_hash =
            from_hex("0001020304050607080900010203040506070809000102030405060708090102").unwrap();

        assert_eq!(pay_request.prefix, "lnbc");
        assert_eq!(pay_request.amount.unwrap(), 250_000_000u64);
        //        assert_eq!(pay_request.payment_hash().unwrap(), payment_hash);
        //        assert_eq!(pay_request.timestamp, 1496314658u64);
        //        //        assert_eq!(pr.nodeId, PublicKey(BinaryData("03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad")));
        //        assert_eq!(
        //            pay_request.description().unwrap().to_string(),
        //            "1 cup coffee".to_owned()
        //        );
        //        assert_eq!(pay_request.fallback_address(), None);
        //        assert_eq!(pay_request.tags.len(), 3);
        //        assert_eq!(pay_request.sign(&SEC_KEY).unwrap().write().unwrap(), tx_ref);
    }

    #[test]
    fn test2() {
        let tx_ref = "lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqscc6gd6ql3jrc5yzme8v4ntcewwz5cnw92tz0pc8qcuufvq7khhr8wpald05e92xw006sq94mg8v2ndf4sefvf9sygkshp5zfem29trqq2yxxz7";
        let pay_request = PaymentRequest::decode(&tx_ref).unwrap();

        let payment_hash =
            from_hex("0001020304050607080900010203040506070809000102030405060708090102").unwrap();

        assert_eq!(pay_request.prefix, "lnbc");
        assert_eq!(pay_request.amount.unwrap(), 2000_000_000u64);
        //        assert_eq!(pay_request.payment_hash().unwrap(), payment_hash);
        //        assert_eq!(pay_request.timestamp, 1496314658u64);
        //        assert_eq!(pay_request.nodeId, PublicKey(BinaryData("03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad")));
        //        assert_eq!(pay_request.description, Right(Crypto.sha256("One piece of chocolate cake, one icecream cone, one pickle, one slice of swiss cheese, one slice of salami, one lollypop, one piece of cherry pie, one sausage, one cupcake, and one slice of watermelon".getBytes)));
        //        assert_eq!(pay_request.fallback_address, None);
        //        assert_eq!(pay_request.tags.len(), 2);
        //        assert_eq!(pr.sign(&SEC_KEY).unwrap().write().unwrap(), tx_ref);
    }
    //    #[test]
    fn test3() {
        let tx_ref = "lntb20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58y\
            jmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfpp3x9et2e20v6pu37c5d9vax37wxq72un98k6\
            vcx9fz94w0qf237cm2rqv9pmn5lnexfvf5579slr4zq3u8kmczecytdx0xg9rwzngp7e6guwqpqlhssu04sucpnz4\
            axcv2dstmknqq6jsk2l";
        let pr = PaymentRequest::decode(&tx_ref).unwrap();
        let payment_hash =
            from_hex("0001020304050607080900010203040506070809000102030405060708090102").unwrap();
        assert_eq!(pr.prefix, "lntb");
        assert_eq!(pr.amount.unwrap(), 2000_000_000u64);
        //            assert_eq!(pr.payment_hash().unwrap(), payment_hash);
        //            assert_eq!(pr.timestamp, 1496314658u64);
        //            assert_eq!(pr.nodeId, PublicKey(BinaryData("03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad")));
        //            assert_eq!(pr.description, Right(Crypto.sha256("One piece of chocolate cake, one icecream cone, one pickle, one slice of swiss cheese, one slice of salami, one lollypop, one piece of cherry pie, one sausage, one cupcake, and one slice of watermelon".getBytes)));
        //            assert_eq!(pr.fallback_address,= Some("mk2QpYatsKicvFVuTAQLBryyccRXMUaGHP"));
        //            assert_eq!(pr.tags.len(), 3);
        //            assert_eq!(pr.sign(&SEC_KEY).unwrap().write().unwrap(), tx_ref);
    }
    #[test]
    fn test4() {
        let tx_ref = "lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp\
            58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfpp3qjmp7lwpagxun9pygexvgpjdc4jdj85fr\
            9yq20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqaf\
            qxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzqj9n4evl6mr5aj9\
            f58zp6fyjzup6ywn3x6sk8akg5v4tgn2q8g4fhx05wf6juaxu9760yp46454gpg5mtzgerlzezqcqvjnhjh8z3g2qq\
            dhhwkj";
        let pay_request = PaymentRequest::decode(&tx_ref).unwrap();
        let payment_hash =
            from_hex("0001020304050607080900010203040506070809000102030405060708090102").unwrap();
        assert_eq!(pay_request.prefix, "lnbc");
        assert_eq!(pay_request.amount.unwrap(), 2000_000_000u64);
        //            assert_eq!(pay_request.payment_hash().unwrap(), payment_hash);
        //            assert_eq!(pay_request.timestamp, 1496314658u64);
        //            assert_eq!(pay_request.nodeId, PublicKey(BinaryData("03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad")));
        //            assert_eq!(pay_request.description, Right(Crypto.sha256("One piece of chocolate cake, one icecream cone, one pickle, one slice of swiss cheese, one slice of salami, one lollypop, one piece of cherry pie, one sausage, one cupcake, and one slice of watermelon".getBytes)));
        //            assert_eq!(pay_request.fallback_address, Some("1RustyRX2oai4EYYDpQGWvEL62BBGqN9T"));
        //            assert_eq!(pay_request.routingInfo, List(List(;
        //                ExtraHop(PublicKey("029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255"), 72623859790382856L, 1, 20, 3),
        //                ExtraHop(PublicKey("039e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255"), 217304205466536202L, 2, 30, 4)
        //            )))
        //            assert_eq!(BinaryData(Protocol.writeUInt64(0x0102030405060708L, ByteOrder.BIG_ENDIAN)), BinaryData("0102030405060708"));
        //            assert_eq!(BinaryData(Protocol.writeUInt64(0x030405060708090aL, ByteOrder.BIG_ENDIAN)), BinaryData("030405060708090a"));
        //            assert_eq!(pr.tags.len(), 4);
        //            assert_eq!(pr.sign(&SEC_KEY).unwrap().write().unwrap(), ref);
    }

}
