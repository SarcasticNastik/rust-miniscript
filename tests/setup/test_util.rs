//! # Miniscript integration test file format
//!
//! This file has custom parsing for miniscripts that enables satisfier to spend transaction
//!
//! K : Compressed key available
//! K!: Compressed key with corresponding secret key unknown
//! X: X-only key available
//! X!: X-only key with corresponding secret key unknown
//!
//! Example:
//! pk(K1)/pkh(X1)/multi(n,...K3,...) represents a compressed key 'K1'/(X-only key 'X1') whose private key in known by the wallet
//! pk(K2!)/pkh(K3!)/multi(n,...K5!,...) represents a key 'K' whose private key is NOT known to the test wallet
//! sha256(H)/hash256(H)/ripemd160(H)/hash160(H) is hash node whose preimage is known to wallet
//! sha256(H!)/hash256(H!)/ripemd160(H!)/hash160(H!) is hash node whose preimage is *NOT* known to wallet
//! timelocks are taken from the transaction value.
//!
//! The keys/hashes are automatically translated so that the tests knows how to satisfy things that don't end with !
//!

use std::str::FromStr;

use actual_rand as rand;
use bitcoin::hashes::hex::ToHex;
use bitcoin::hashes::{hash160, ripemd160, sha256, sha256d, Hash};
use bitcoin::secp256k1;
use miniscript::descriptor::{SinglePub, SinglePubKey};
use miniscript::{
    Descriptor, DescriptorPublicKey, Miniscript, ScriptContext, TranslatePk, Translator,
};
use rand::RngCore;

#[derive(Clone, Debug)]
pub struct PubData {
    pub pks: Vec<bitcoin::PublicKey>,
    pub x_only_pks: Vec<bitcoin::XOnlyPublicKey>,
    pub sha256: sha256::Hash,
    pub hash256: sha256d::Hash,
    pub ripemd160: ripemd160::Hash,
    pub hash160: hash160::Hash,
}

#[derive(Debug, Clone)]
pub struct SecretData {
    pub sks: Vec<bitcoin::secp256k1::SecretKey>,
    pub x_only_keypairs: Vec<bitcoin::KeyPair>,
    pub sha256_pre: [u8; 32],
    pub hash256_pre: [u8; 32],
    pub ripemd160_pre: [u8; 32],
    pub hash160_pre: [u8; 32],
}
#[derive(Debug, Clone)]
pub struct TestData {
    pub pubdata: PubData,
    pub secretdata: SecretData,
}

// Setup (sk, pk) pairs
fn setup_keys(
    n: usize,
) -> (
    Vec<bitcoin::secp256k1::SecretKey>,
    Vec<miniscript::bitcoin::PublicKey>,
    Vec<bitcoin::KeyPair>,
    Vec<bitcoin::XOnlyPublicKey>,
) {
    let secp_sign = secp256k1::Secp256k1::signing_only();
    let mut sk = [0; 32];
    let mut sks = vec![];
    let mut pks = vec![];
    for i in 1..n + 1 {
        sk[0] = i as u8;
        sk[1] = (i >> 8) as u8;
        sk[2] = (i >> 16) as u8;

        let sk = secp256k1::SecretKey::from_slice(&sk[..]).expect("secret key");
        let pk = miniscript::bitcoin::PublicKey {
            inner: secp256k1::PublicKey::from_secret_key(&secp_sign, &sk),
            compressed: true,
        };
        pks.push(pk);
        sks.push(sk);
    }

    let mut x_only_keypairs = vec![];
    let mut x_only_pks = vec![];

    for i in 0..n {
        let keypair = bitcoin::KeyPair::from_secret_key(&secp_sign, sks[i]);
        let xpk = bitcoin::XOnlyPublicKey::from_keypair(&keypair);
        x_only_keypairs.push(keypair);
        x_only_pks.push(xpk);
    }
    (sks, pks, x_only_keypairs, x_only_pks)
}

impl TestData {
    // generate a fixed data for n keys
    pub(crate) fn new_fixed_data(n: usize) -> Self {
        let (sks, pks, x_only_keypairs, x_only_pks) = setup_keys(n);
        let sha256_pre = [0x12 as u8; 32];
        let sha256 = sha256::Hash::hash(&sha256_pre);
        let hash256_pre = [0x34 as u8; 32];
        let hash256 = sha256d::Hash::hash(&hash256_pre);
        let hash160_pre = [0x56 as u8; 32];
        let hash160 = hash160::Hash::hash(&hash160_pre);
        let ripemd160_pre = [0x78 as u8; 32];
        let ripemd160 = ripemd160::Hash::hash(&ripemd160_pre);

        let pubdata = PubData {
            pks,
            sha256,
            hash256,
            ripemd160,
            hash160,
            x_only_pks,
        };
        let secretdata = SecretData {
            sks,
            sha256_pre,
            hash256_pre,
            ripemd160_pre,
            hash160_pre,
            x_only_keypairs,
        };
        Self {
            pubdata,
            secretdata,
        }
    }
}

/// Obtain an insecure random public key with unknown secret key for testing
pub fn random_pk(mut seed: u8) -> bitcoin::PublicKey {
    loop {
        let mut data = [0; 33];
        for byte in &mut data[..] {
            *byte = seed;
            // totally a rng
            seed = seed.wrapping_mul(41).wrapping_add(53);
        }
        data[0] = 2 + (data[0] >> 7);
        if let Ok(key) = bitcoin::PublicKey::from_slice(&data[..33]) {
            return key;
        }
    }
}

#[allow(dead_code)]
// https://github.com/rust-lang/rust/issues/46379. The code is pub fn and integration test, but still shows warnings
/// Parse an insane miniscript into a miniscript with the format described above at file header
pub fn parse_insane_ms<Ctx: ScriptContext>(
    ms: &str,
    pubdata: &PubData,
) -> Miniscript<DescriptorPublicKey, Ctx> {
    let ms = subs_hash_frag(ms, pubdata);
    let ms =
        Miniscript::<String, Ctx>::from_str_insane(&ms).expect("only parsing valid minsicripts");
    let mut translator = StrTranslatorLoose(0, pubdata);
    let ms = ms.translate_pk(&mut translator).unwrap();
    ms
}

// Translate Str to DescriptorPublicKey
#[derive(Debug, Clone)]
struct StrDescPubKeyTranslator<'a>(usize, &'a PubData);

impl<'a> Translator<String, DescriptorPublicKey, ()> for StrDescPubKeyTranslator<'a> {
    fn pk(&mut self, pk_str: &String) -> Result<DescriptorPublicKey, ()> {
        let avail = !pk_str.ends_with("!");
        if avail {
            self.0 = self.0 + 1;
            if pk_str.starts_with("K") {
                Ok(DescriptorPublicKey::Single(SinglePub {
                    origin: None,
                    key: SinglePubKey::FullKey(self.1.pks[self.0]),
                }))
            } else if pk_str.starts_with("X") {
                Ok(DescriptorPublicKey::Single(SinglePub {
                    origin: None,
                    key: SinglePubKey::XOnly(self.1.x_only_pks[self.0]),
                }))
            } else {
                panic!("Key must start with either K or X")
            }
        } else {
            Ok(DescriptorPublicKey::Single(SinglePub {
                origin: None,
                key: SinglePubKey::FullKey(random_pk(59)),
            }))
        }
    }

    fn pkh(&mut self, pkh: &String) -> Result<DescriptorPublicKey, ()> {
        self.pk(pkh)
    }

    fn sha256(&mut self, sha256: &String) -> Result<sha256::Hash, ()> {
        let sha = sha256::Hash::from_str(sha256).unwrap();
        Ok(sha)
    }
}

// Translate Str to DescriptorPublicKey
// Same as StrDescPubKeyTranslator, but does not panic when Key is not starting with
// K or X. This is used when testing vectors from C++ to rust
#[derive(Debug, Clone)]
struct StrTranslatorLoose<'a>(usize, &'a PubData);

impl<'a> Translator<String, DescriptorPublicKey, ()> for StrTranslatorLoose<'a> {
    fn pk(&mut self, pk_str: &String) -> Result<DescriptorPublicKey, ()> {
        let avail = !pk_str.ends_with("!");
        if avail {
            self.0 = self.0 + 1;
            if pk_str.starts_with("K") {
                Ok(DescriptorPublicKey::Single(SinglePub {
                    origin: None,
                    key: SinglePubKey::FullKey(self.1.pks[self.0]),
                }))
            } else if pk_str.starts_with("X") {
                Ok(DescriptorPublicKey::Single(SinglePub {
                    origin: None,
                    key: SinglePubKey::XOnly(self.1.x_only_pks[self.0]),
                }))
            } else {
                // Parse any other keys as known to allow compatibility with existing tests
                Ok(DescriptorPublicKey::Single(SinglePub {
                    origin: None,
                    key: SinglePubKey::FullKey(self.1.pks[self.0]),
                }))
            }
        } else {
            Ok(DescriptorPublicKey::Single(SinglePub {
                origin: None,
                key: SinglePubKey::FullKey(random_pk(59)),
            }))
        }
    }

    fn pkh(&mut self, pkh: &String) -> Result<DescriptorPublicKey, ()> {
        self.pk(pkh)
    }

    fn sha256(&mut self, sha256: &String) -> Result<sha256::Hash, ()> {
        let sha = sha256::Hash::from_str(sha256).unwrap();
        Ok(sha)
    }
}

#[allow(dead_code)]
// https://github.com/rust-lang/rust/issues/46379. The code is pub fn and integration test, but still shows warnings
pub fn parse_test_desc(desc: &str, pubdata: &PubData) -> Descriptor<DescriptorPublicKey> {
    let desc = subs_hash_frag(desc, pubdata);
    let desc =
        Descriptor::<String>::from_str(&desc).expect("only parsing valid and sane descriptors");
    let mut translator = StrDescPubKeyTranslator(0, pubdata);
    let desc: Result<_, ()> = desc.translate_pk(&mut translator);
    desc.expect("Translate must succeed")
}

// substitute hash fragments in the string as the per rules
fn subs_hash_frag(ms: &str, pubdata: &PubData) -> String {
    let ms = ms.replace(
        "sha256(H)",
        &format!("sha256({})", &pubdata.sha256.to_hex()),
    );
    let ms = ms.replace(
        "hash256(H)",
        &format!("hash256({})", &pubdata.hash256.into_inner().to_hex()),
    );
    let ms = ms.replace(
        "ripemd160(H)",
        &format!("ripemd160({})", &pubdata.ripemd160.to_hex()),
    );
    let ms = ms.replace(
        "hash160(H)",
        &format!("hash160({})", &pubdata.hash160.to_hex()),
    );

    let mut rand_hash32 = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut rand_hash32);

    let mut rand_hash20 = [0u8; 20];
    rand::thread_rng().fill_bytes(&mut rand_hash20);
    let ms = ms.replace("sha256(H!)", &format!("sha256({})", rand_hash32.to_hex()));
    let ms = ms.replace("hash256(H!)", &format!("hash256({})", rand_hash32.to_hex()));
    let ms = ms.replace(
        "ripemd160(H!)",
        &format!("ripemd160({})", rand_hash20.to_hex()),
    );
    let ms = ms.replace("hash160(H!)", &format!("hash160({})", rand_hash20.to_hex()));
    ms
}
