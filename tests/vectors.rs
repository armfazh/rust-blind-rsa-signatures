use blind_rsa_signatures::{Hash, Options, PSSMode, PrepareMode, SecretKey};
use num_bigint_dig::traits::ModInverse;
use num_traits::{Num, Zero};
use rsa::BigUint;
use serde::{Deserialize, Deserializer};
use std::{fs::File, vec};

#[derive(Deserialize)]
struct Vector {
    name: String,
    #[serde(deserialize_with = "parse_number")]
    p: BigUint,
    #[serde(deserialize_with = "parse_number")]
    q: BigUint,
    #[serde(deserialize_with = "parse_number")]
    n: BigUint,
    #[serde(deserialize_with = "parse_number")]
    e: BigUint,
    #[serde(deserialize_with = "parse_number")]
    d: BigUint,
    #[serde(deserialize_with = "parse_number")]
    inv: BigUint,
    #[serde(deserialize_with = "parse_bytes")]
    msg: Vec<u8>,
    #[serde(deserialize_with = "parse_bytes")]
    msg_prefix: Vec<u8>,
    #[serde(deserialize_with = "parse_usize", rename = "sLen")]
    salt_len: usize,
    #[serde(deserialize_with = "parse_bytes")]
    salt: Vec<u8>,
    #[serde(deserialize_with = "parse_bool")]
    is_randomized: bool,
    #[serde(deserialize_with = "parse_bytes")]
    blinded_msg: Vec<u8>,
    #[serde(deserialize_with = "parse_bytes")]
    blind_sig: Vec<u8>,
    #[serde(deserialize_with = "parse_bytes")]
    sig: Vec<u8>,
}

fn parse_bool<'a, D: Deserializer<'a>>(deserializer: D) -> Result<bool, D::Error> {
    let s: String = Deserialize::deserialize(deserializer)?;
    hex::decode(&s[2..])
        .map(|b| b[0] != 0)
        .map_err(|e| serde::de::Error::custom(e.to_string()))
}

fn parse_usize<'a, D: Deserializer<'a>>(deserializer: D) -> Result<usize, D::Error> {
    let s: String = Deserialize::deserialize(deserializer)?;
    hex::decode(&s[2..])
        .map(|b| b[0] as usize)
        .map_err(|e| serde::de::Error::custom(e.to_string()))
}

fn parse_number<'a, D: Deserializer<'a>>(deserializer: D) -> Result<BigUint, D::Error> {
    let s: String = Deserialize::deserialize(deserializer)?;
    BigUint::from_str_radix(&s[2..], 16).map_err(|e| serde::de::Error::custom(e.to_string()))
}

fn parse_bytes<'a, D: Deserializer<'a>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    let s: String = Deserialize::deserialize(deserializer)?;
    hex::decode(s).map_err(|e| serde::de::Error::custom(e.to_string()))
}

struct MockRandom(Vec<Vec<u8>>);
impl rsa::rand_core::CryptoRng for MockRandom {}
impl rsa::rand_core::RngCore for MockRandom {
    fn next_u32(&mut self) -> u32 {
        unimplemented!()
    }

    fn next_u64(&mut self) -> u64 {
        unimplemented!()
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        dst.copy_from_slice(&self.0.remove(0));
    }

    fn try_fill_bytes(&mut self, _dst: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
        unimplemented!()
    }
}

#[test]
fn rfc9474() {
    const FILENAME: &str = "tests/test_vectors_rfc9474.json";
    let vectors: Vec<Vector> = serde_json::from_reader(File::open(FILENAME).unwrap()).unwrap();

    for vector in vectors {
        println!("Testing {}", vector.name);

        let options = Options::new(
            Hash::Sha384,
            if vector.salt_len.is_zero() {
                PSSMode::PSSZero
            } else {
                PSSMode::PSS
            },
            if vector.is_randomized {
                PrepareMode::Randomized
            } else {
                PrepareMode::Deterministic
            },
        );

        // Mock random number generator.
        let mut mock_rng = MockRandom({
            let (_, r) = (&vector.inv).mod_inverse(&vector.n).unwrap().to_bytes_be();
            let mut out = Vec::with_capacity(3);
            if options.is_randomized() {
                out.push(vector.msg_prefix);
            }
            out.push(vector.salt);
            out.push(r);
            out
        });

        // Parse signing keys.
        let sk = SecretKey(
            rsa::RsaPrivateKey::from_components(
                vector.n,
                vector.e,
                vector.d,
                vec![vector.p, vector.q],
            )
            .unwrap(),
        );
        let pk = sk.public_key().unwrap();

        // Client blinds a message to be signed.
        let result = pk.blind(&mut mock_rng, &vector.msg, &options).unwrap();
        assert_eq!(result.secret.0, vector.inv.to_bytes_be());
        assert_eq!(result.blind_msg.0, vector.blinded_msg);

        // Server signs a blinded message producing a blinded signature.
        let blinded_sig = sk.blind_sign(&result.blind_msg, &options).unwrap();
        assert_eq!(blinded_sig.0, vector.blind_sig);

        // Client computes the final RSA signature.
        let signature = pk
            .finalize(&blinded_sig, &result, &vector.msg, &options)
            .unwrap();
        assert_eq!(signature.0, vector.sig);

        // RSA signature can be verified with the public key.
        assert!(signature
            .verify(&pk, result.msg_randomizer, vector.msg, &options)
            .is_ok());
    }
}
