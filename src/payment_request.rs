use bech32::{Bech32, create_checksum as bech32_checksum, CHARSET};
use tag::{ExtraHop, Tag};
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
#[derive(Debug, Clone, PartialEq, Eq)]
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

//impl Default for PaymentRequest {
//
//}

impl PaymentRequest {

    /// decode parses the provided encoded invoice and returns a decoded Invoice if
    /// it is valid by BOLT11 and matches the provided active network.
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
                    //  the recovery id is the last byte of the signature
                    let recovery_id = secp256k1::RecoveryId::parse(signature_bytes[64])?;
                    let signature = PaymentRequest::parse_signature(&signature_bytes[..64]);
                    (recovery_id, signature)
                };

                let message = PaymentRequest::parse_message(&hrp, &data.to_u8_vec(true)?);
                let timestamp = Timestamp::decode(&data.drain(..7).collect::<Vec<_>>());
                let tags = Tag::parse_all(&data)?;

                let node_id = secp256k1::recover(&message, &signature, &recovery_id)?;

                let prefix = hrp[..4].to_owned();
                let amount = hrp.get(4..).and_then(|u| Amount::decode(u).ok());
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

    /// encode to bech32 payment request
    pub fn encode(&self) -> Result<String, Error> {
        let hr_amount = self.amount.map_or(String::new(), |a| Amount::encode(a));
        let mut hrp = self.prefix.to_owned() + &hr_amount;
        let stream = [
            self.stream(),
            self.signature.serialize().to_vec().to_u5_vec(true)?,
            vec![self.recovery_id],
        ].concat();

        let checksum = bech32_checksum(&hrp.as_bytes().to_vec(), &stream);
        let stream_sum = [stream, checksum]
            .concat()
            .iter()
            .map(|i| CHARSET[*i as usize])
            .collect::<String>();
        hrp.push_str("1");
        hrp.push_str(&stream_sum);
        Ok(hrp)
    }

    /// update payment amoount
    pub fn update_amount(&mut self, amount: Option<u64>) {
        self.amount = amount;
    }

    /// update public key of the payee node
    pub fn update_node_id(&mut self, node_id: PublicKey) {
        self.node_id = node_id;
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

    /// update the payment description
    /// *Note*: must be used if and only if description hash is not used.
    pub fn update_description(&mut self, description: String) {
        let mut tags = self.filter_description();
        tags.push(Tag::Description { description });
        self.tags = tags
    }

    /// extra rounting info
    pub fn routing_info(&self) -> Vec<ExtraHop> {
        self.tags
            .iter()
            .filter_map(|v| match *v {
                Tag::RoutingInfo { ref path } => Some(path.to_owned()),
                _ => None,
            })
            .flatten()
            .collect_vec()
    }

    /// min final cltv expiry
    /// optional value which allows the receiver of the payment to specify the delta between the
    /// current height and the HTLC extended to the receiver.
    pub fn min_final_cltv_expiry(&self) -> Option<u64> {
        self.tags
            .iter()
            .filter_map(|v| match *v {
                Tag::MinFinalCltvExpiry { blocks } => Some(blocks),
                _ => None,
            })
            .next()
    }
    /// update min final cltv expiry
    pub fn update_min_final_cltv_expiry(&mut self, blocks: u64) {
        let mut tags = self.tags
            .iter()
            .filter(|t| !matches!(*t, &Tag::MinFinalCltvExpiry{..}))
            .map(|t| t.to_owned())
            .collect::<Vec<Tag>>();
        tags.push(Tag::MinFinalCltvExpiry { blocks });
        self.tags = tags;
    }

    /// expiry
    pub fn expiry(&self) -> Option<u64> {
        self.tags
            .iter()
            .filter_map(|v| match *v {
                Tag::Expiry { seconds } => Some(seconds),
                _ => None,
            })
            .next()
    }

    /// update expiry
    pub fn update_expiry(&mut self, seconds: u64) {
        let mut tags = self.tags
            .iter()
            .filter(|t| !matches!(*t, &Tag::Expiry{..}))
            .map(|t| t.to_owned())
            .collect::<Vec<Tag>>();
        tags.push(Tag::Expiry { seconds });
        self.tags = tags;
    }
    /// description hash
    pub fn description_hash(&self) -> Option<Vec<u8>> {
        self.tags
            .iter()
            .filter_map(|v| match *v {
                Tag::DescriptionHash { ref hash } => Some(hash.to_owned()),
                _ => None,
            })
            .next()
    }

    // update the payment description hash
    // Note: must be used if and only if description is not used.
    pub fn update_description_hash(&mut self, hash: Vec<u8>) {
        let mut tags = self.filter_description();
        tags.push(Tag::DescriptionHash { hash });
        self.tags = tags;
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

    /// update fallback address
    pub fn update_fallback_address(&mut self, version: u8, hash: Vec<u8>) {
        let mut tags = self.tags
            .iter()
            .filter(|t| !matches!(*t, &Tag::FallbackAddress{..}))
            .map(|t| t.to_owned())
            .collect::<Vec<Tag>>();
        tags.push(Tag::FallbackAddress { version, hash });
        self.tags = tags
    }

    /// the hash of this payment request
    pub fn hash(&self) -> Result<Vec<u8>, Error> {
        let amount = self.amount.map_or(String::new(), |a| Amount::encode(a));
        let bytes = (self.prefix.to_owned() + &amount).as_bytes().to_vec();

        Ok(
            PaymentRequest::sha256_hasher(&[bytes, self.stream().to_u8_vec(false)?].concat())
                .to_vec(),
        )
    }

    /// sign a payment request
    pub fn sign(&self, secret_key: &SecretKey) -> Result<PaymentRequest, Error> {
        match secp256k1::sign(&self.message, secret_key) {
            Ok((signature, recovery_id)) => {
                let mut signed = self.clone();
                signed.signature = signature;
                signed.recovery_id = recovery_id.serialize();
                Ok(signed)
            }
            Err(e) => Err(Error::SignatureError(e)),
        }
    }

    /// a representation of this payment request, without its signature, as a bit stream. This is what will be signed
    fn stream(&self) -> Vec<U5> {
        //Result<Vec<u8>, Error> {
        let bytes = self.tags
            .iter()
            .flat_map(|tag| tag.to_vec_u5())
            .collect_vec()
            .concat();
        [Timestamp::encode(self.timestamp), bytes].concat()
    }
    // remove the payment description
    fn filter_description(&self) -> Vec<Tag> {
        self.tags
            .iter()
            .filter(|t| {
                !matches!(*t, &Tag::Description{..}) && !matches!(*t, &Tag::DescriptionHash{..} )
            })
            .map(|t| t.to_owned())
            .collect::<Vec<Tag>>()
    }

    // parse the message
    fn parse_message(hrp: &String, bytes: &[u8]) -> Message {
        let message_bytes = [hrp.as_bytes(), bytes].concat();
        let raw_message = PaymentRequest::sha256_hasher(&message_bytes);

        secp256k1::Message::parse(&raw_message)
    }

    fn sha256_hasher(bytes: &[u8]) -> [u8; 32] {
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
    use utils::{from_hex, to_hex};

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
    fn test_field_update() {
        let tx_ref = "lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqd\
        q5xysxxatsyp3k7enxv4jsxqzpuaztrnwngzn3kdzw5hydlzf03qdgm2hdq27cqv3agm2awhz5se903vruatfhq77w\
        3ls4evs3ch9zw97j25emudupq63nyw24cg27h2rspfj9srp";
        let mut pay_request = PaymentRequest::decode(&tx_ref).unwrap();

        let amount = Some(850_000_000u64);
        pay_request.update_amount(amount);
        assert_eq!(pay_request.amount, amount);

        let description = "ナンセンス 1杯";
        pay_request.update_description(description.to_owned());
        assert_eq!(pay_request.description().unwrap().to_string(), description);

        let fallback_address = Some("1RustyRX2oai4EYYDpQGWvEL62BBGqN9T".to_owned());
        let fallback_hash = vec![
            4, 182, 31, 125, 193, 234, 13, 201, 148, 36, 70, 76, 196, 6, 77, 197, 100, 217, 30, 137
        ];
        pay_request.update_fallback_address(17, fallback_hash);
        assert_eq!(pay_request.fallback_address(), fallback_address)
    }

    #[test]
    fn test_send_using_payment_hash() {
        // Please make a donation of any amount using payment_hash 0001020304050607080900010203040506070809000102030405060708090102 to me @03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad
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
        assert!(pay_request.node_id.eq(&PUB_KEY));
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
        assert_eq!(
            PaymentRequest::decode(&pay_request.encode().unwrap()).unwrap(),
            pay_request
        );
    }

    #[test]
    fn test_send_to_the_same_peer_within_1_minute() {
        // Please send $3 for a cup of coffee to the same peer, within 1 minute
        let tx_ref = "lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqd\
        q5xysxxatsyp3k7enxv4jsxqzpuaztrnwngzn3kdzw5hydlzf03qdgm2hdq27cqv3agm2awhz5se903vruatfhq77w\
        3ls4evs3ch9zw97j25emudupq63nyw24cg27h2rspfj9srp";
        let pay_request = PaymentRequest::decode(&tx_ref).unwrap();
        let payment_hash =
            from_hex("0001020304050607080900010203040506070809000102030405060708090102").unwrap();

        assert_eq!(pay_request.prefix, "lnbc");
        assert_eq!(pay_request.amount, Some(250_000_000u64));
        assert_eq!(pay_request.payment_hash().unwrap(), payment_hash);
        assert_eq!(pay_request.timestamp, 1496314658u64);
        assert!(pay_request.node_id.eq(&PUB_KEY));
        assert_eq!(
            pay_request.description().unwrap().to_string(),
            "1 cup coffee".to_owned()
        );
        assert_eq!(pay_request.fallback_address(), None);
        assert_eq!(pay_request.tags.len(), 3);
        assert_eq!(pay_request.encode().unwrap(), tx_ref);
        assert_eq!(
            pay_request.sign(&SEC_KEY).unwrap().encode().unwrap(),
            tx_ref
        );
    }

    #[test]
    fn test_send_for_an_entire_list_of_things_hashed() {
        // Now send $24 for an entire list of things (hashed)
        let tx_ref =
            "lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqh\
             p58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqscc6gd6ql3jrc5yzme8v4ntcewwz5cnw9\
             2tz0pc8qcuufvq7khhr8wpald05e92xw006sq94mg8v2ndf4sefvf9sygkshp5zfem29trqq2yxxz7";
        let pay_request = PaymentRequest::decode(&tx_ref).unwrap();

        let payment_hash =
            from_hex("0001020304050607080900010203040506070809000102030405060708090102").unwrap();

        assert_eq!(pay_request.prefix, "lnbc");
        assert_eq!(pay_request.amount, Some(2000_000_000u64));
        assert_eq!(pay_request.payment_hash(), Some(payment_hash));
        assert_eq!(pay_request.timestamp, 1496314658u64);
        assert!(pay_request.node_id.eq(&PUB_KEY));
        assert_eq!(
            pay_request.description().unwrap().to_string(),
            "3925b6f67e2c340036ed12093dd44e0368df1b6ea26c53dbe4811f58fd5db8c1".to_owned()
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
    fn test_send_for_an_entire_list_of_things_hashed_on_testnet_with_fallback_address() {
        // The same, on testnet, with a fallback address mk2QpYatsKicvFVuTAQLBryyccRXMUaGHP
        let tx_ref = "lntb20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58y\
            jmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfpp3x9et2e20v6pu37c5d9vax37wxq72un98k6\
            vcx9fz94w0qf237cm2rqv9pmn5lnexfvf5579slr4zq3u8kmczecytdx0xg9rwzngp7e6guwqpqlhssu04sucpnz4\
            axcv2dstmknqq6jsk2l";
        let pay_request = PaymentRequest::decode(&tx_ref).unwrap();
        let payment_hash =
            from_hex("0001020304050607080900010203040506070809000102030405060708090102").unwrap();
        assert_eq!(pay_request.prefix, "lntb");
        assert_eq!(pay_request.amount, Some(2000_000_000u64));
        assert_eq!(pay_request.payment_hash(), Some(payment_hash));
        assert_eq!(pay_request.timestamp, 1496314658u64);
        assert!(pay_request.node_id.eq(&PUB_KEY));
        assert_eq!(
            pay_request.description().unwrap().to_string(),
            "3925b6f67e2c340036ed12093dd44e0368df1b6ea26c53dbe4811f58fd5db8c1".to_owned()
        );
        assert_eq!(
            pay_request.fallback_address(),
            Some("mk2QpYatsKicvFVuTAQLBryyccRXMUaGHP".to_owned())
        );
        assert_eq!(pay_request.tags.len(), 3);
        assert_eq!(pay_request.encode().unwrap(), tx_ref);
        assert_eq!(
            pay_request.sign(&SEC_KEY).unwrap().encode().unwrap(),
            tx_ref
        );
    }
    #[test]
    fn test_on_mainnet_with_fallback_address_with_extra_routing_info_via_nodes() {
        // On mainnet, with fallback address 1RustyRX2oai4EYYDpQGWvEL62BBGqN9T with extra routing
        // info to go via nodes 029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255
        // then 039e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255"
        let tx_ref = "lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp\
            58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfpp3qjmp7lwpagxun9pygexvgpjdc4jdj85fr\
            9yq20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqaf\
            qxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzqj9n4evl6mr5aj9\
            f58zp6fyjzup6ywn3x6sk8akg5v4tgn2q8g4fhx05wf6juaxu9760yp46454gpg5mtzgerlzezqcqvjnhjh8z3g2qq\
            dhhwkj";
        let pay_request = PaymentRequest::decode(&tx_ref).unwrap();
        let payment_hash =
            from_hex("0001020304050607080900010203040506070809000102030405060708090102").unwrap();
        let routing_info = Tag::RoutingInfo {
            path: vec![
                ExtraHop {
                    pub_key: from_hex(
                        "029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255",
                    ).unwrap(),
                    short_channel_id: 72623859790382856u64,
                    fee_base_msat: 1,
                    fee_proportional_millionths: 20,
                    cltv_expiry_delta: 3,
                },
                ExtraHop {
                    pub_key: from_hex(
                        "039e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255",
                    ).unwrap(),
                    short_channel_id: 217304205466536202u64,
                    fee_base_msat: 2,
                    fee_proportional_millionths: 30,
                    cltv_expiry_delta: 4,
                },
            ],
        };

        assert_eq!(pay_request.prefix, "lnbc");
        assert_eq!(pay_request.amount, Some(2000_000_000u64));
        assert_eq!(pay_request.payment_hash(), Some(payment_hash));
        assert_eq!(pay_request.timestamp, 1496314658u64);
        assert!(pay_request.node_id.eq(&PUB_KEY));
        assert_eq!(
            pay_request.description().unwrap().to_string(),
            "3925b6f67e2c340036ed12093dd44e0368df1b6ea26c53dbe4811f58fd5db8c1".to_owned()
        );
        assert_eq!(
            pay_request.fallback_address(),
            Some("1RustyRX2oai4EYYDpQGWvEL62BBGqN9T".to_owned())
        );
        assert_eq!(
            Tag::RoutingInfo {
                path: pay_request.routing_info(),
            },
            routing_info
        );
        assert_eq!(pay_request.tags.len(), 4);
        assert_eq!(pay_request.encode().unwrap(), tx_ref);
        assert_eq!(
            pay_request.sign(&SEC_KEY).unwrap().encode().unwrap(),
            tx_ref
        );
    }

    #[test]
    fn test_on_mainnet_with_fallback_address_p2sh() {
        // On mainnet, with fallback (p2sh) address 3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX
        let tx_ref = "lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp5\
                8yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfppj3a24vwu6r8ejrss3axul8rxldph2q7z9kk\
                822r8plup77n9yq5ep2dfpcydrjwzxs0la84v3tfw43t3vqhek7f05m6uf8lmfkjn7zv7enn76sq65d8u9lxav2pl6\
                x3xnc2ww3lqpagnh0u";
        let pay_request = PaymentRequest::decode(&tx_ref).unwrap();
        let payment_hash =
            from_hex("0001020304050607080900010203040506070809000102030405060708090102").unwrap();

        assert_eq!(pay_request.prefix, "lnbc");
        assert_eq!(pay_request.amount, Some(2000000000u64));
        assert_eq!(pay_request.payment_hash(), Some(payment_hash));
        assert_eq!(pay_request.timestamp, 1496314658u64);
        assert!(pay_request.node_id.eq(&PUB_KEY));
        assert_eq!(
            pay_request.description().unwrap().to_string(),
            "3925b6f67e2c340036ed12093dd44e0368df1b6ea26c53dbe4811f58fd5db8c1".to_owned()
        );
        assert_eq!(
            pay_request.fallback_address(),
            Some("3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX".to_owned())
        );
        assert_eq!(pay_request.tags.len(), 3);
        assert_eq!(pay_request.encode().unwrap(), tx_ref);
        assert_eq!(
            pay_request.sign(&SEC_KEY).unwrap().encode().unwrap(),
            tx_ref
        );
    }
    #[test]
    fn test_on_mainnet_with_fallback_p2wpkh_address() {
        // On mainnet, with Fallback (p2wpkh) address bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
        let tx_ref = "lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58\
                yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfppqw508d6qejxtdg4y5r3zarvary0c5xw7kknt\
                6zz5vxa8yh8jrnlkl63dah48yh6eupakk87fjdcnwqfcyt7snnpuz7vp83txauq4c60sys3xyucesxjf46yqnpplj\
                0saq36a554cp9wt865";
        let pay_request = PaymentRequest::decode(&tx_ref).unwrap();
        let payment_hash =
            from_hex("0001020304050607080900010203040506070809000102030405060708090102").unwrap();

        assert_eq!(pay_request.prefix, "lnbc");
        assert_eq!(pay_request.amount, Some(2000000000u64));
        assert_eq!(pay_request.payment_hash(), Some(payment_hash));
        assert_eq!(pay_request.timestamp, 1496314658u64);
        assert!(pay_request.node_id.eq(&PUB_KEY));
        assert_eq!(
            pay_request.description().unwrap().to_string(),
            "3925b6f67e2c340036ed12093dd44e0368df1b6ea26c53dbe4811f58fd5db8c1".to_owned()
        );
        assert_eq!(
            pay_request.fallback_address(),
            Some("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_owned())
        );
        assert_eq!(pay_request.tags.len(), 3);
        assert_eq!(pay_request.encode().unwrap(), tx_ref);
        assert_eq!(
            pay_request.sign(&SEC_KEY).unwrap().encode().unwrap(),
            tx_ref
        );
    }

    #[test]
    fn test_on_mainnet_with_fallback_address_p2wsh() {
        //  On mainnet, with __fallback (p2wsh) address bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3
        let tx_ref = "lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58y\
            jmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfp4qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4x\
            j0gdcccefvpysxf3qvnjha2auylmwrltv2pkp2t22uy8ura2xsdwhq5nm7s574xva47djmnj2xeycsu7u5v8929mvu\
            ux43j0cqhhf32wfyn2th0sv4t9x55sppz5we8";
        let pay_request = PaymentRequest::decode(&tx_ref).unwrap();
        let payment_hash =
            from_hex("0001020304050607080900010203040506070809000102030405060708090102").unwrap();
        assert_eq!(pay_request.prefix, "lnbc");
        assert_eq!(pay_request.amount, Some(2000000000u64));
        assert_eq!(pay_request.payment_hash(), Some(payment_hash));
        assert_eq!(pay_request.timestamp, 1496314658u64);
        assert!(pay_request.node_id.eq(&PUB_KEY));
        assert_eq!(
            pay_request.description().unwrap().to_string(),
            "3925b6f67e2c340036ed12093dd44e0368df1b6ea26c53dbe4811f58fd5db8c1".to_owned()
        );
        assert_eq!(
            pay_request.fallback_address(),
            Some("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3".to_owned())
        );
        assert_eq!(pay_request.tags.len(), 3);
        assert_eq!(pay_request.encode().unwrap(), tx_ref);
        assert_eq!(
            pay_request.sign(&SEC_KEY).unwrap().encode().unwrap(),
            tx_ref
        );
    }
    #[test]
    fn test_on_mainnet_with_fallback_address_p2wsh_and_minimum_htlc_cltv_expiry() {
        //  On mainnet, with _Fallback (p2wsh) address bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3 and a minimum htlc cltv expiry of 12
        let tx_ref = "lnbc20m1pvjluezcqpvpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqh\
            p58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfp4qrp33g0q5c5txsp9arysrx4k6zdkfs4nc\
            e4xj0gdcccefvpysxf3q90qkf3gd7fcqs0ewr7t3xf72ptmc4n38evg0xhy4p64nlg7hgrmq6g997tkrvezs8afs0\
            x0y8v4vs8thwsk6knkvdfvfa7wmhhpcsxcqw0ny48";
        let pay_request = PaymentRequest::decode(&tx_ref).unwrap();
        let payment_hash =
            from_hex("0001020304050607080900010203040506070809000102030405060708090102").unwrap();
        assert_eq!(pay_request.prefix, "lnbc");
        assert_eq!(pay_request.amount, Some(2000000000u64));
        assert_eq!(pay_request.payment_hash(), Some(payment_hash));
        assert_eq!(pay_request.timestamp, 1496314658u64);
        assert!(pay_request.node_id.eq(&PUB_KEY));
        assert_eq!(
            pay_request.description().unwrap().to_string(),
            "3925b6f67e2c340036ed12093dd44e0368df1b6ea26c53dbe4811f58fd5db8c1".to_owned()
        );
        assert_eq!(
            pay_request.fallback_address(),
            Some("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3".to_owned())
        );
        assert_eq!(pay_request.min_final_cltv_expiry(), Some(12));
        assert_eq!(pay_request.tags.len(), 4);
        assert_eq!(pay_request.encode().unwrap(), tx_ref);
        assert_eq!(
            pay_request.sign(&SEC_KEY).unwrap().encode().unwrap(),
            tx_ref
        );
    }

    #[test]
    fn test_send_for_cup_of_nonsense_to_the_same_peer() {
        //Please send 0.0025 BTC for a cup of nonsense (ナンセンス 1杯) to the same peer, within 1 minute
        let tx_ref = "lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqyp\
        qdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpuyk0sg5g70me25alkluzd2x62aysf2pyy8edtjeevuv4p2d5p7\
        6r4zkmneet7uvyakky2zr4cusd45tftc9c5fh0nnqpnl2jfll544esqchsrny";
        let pay_request = PaymentRequest::decode(&tx_ref).unwrap();
        let payment_hash =
            from_hex("0001020304050607080900010203040506070809000102030405060708090102").unwrap();
        assert_eq!(pay_request.prefix, "lnbc");
        assert_eq!(pay_request.amount, Some(250_000_000u64));
        assert_eq!(pay_request.payment_hash(), Some(payment_hash));
        assert_eq!(pay_request.timestamp, 1496314658u64);
        assert!(pay_request.node_id.eq(&PUB_KEY));
        assert_eq!(
            pay_request.description().unwrap().to_string(),
            "ナンセンス 1杯".to_owned()
        );
        assert_eq!(pay_request.expiry(), Some(60));
        assert_eq!(pay_request.tags.len(), 3);
        assert_eq!(pay_request.encode().unwrap(), tx_ref);
        assert_eq!(
            pay_request.sign(&SEC_KEY).unwrap().encode().unwrap(),
            tx_ref
        );
    }

}
