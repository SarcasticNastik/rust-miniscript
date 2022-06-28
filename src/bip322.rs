// BIP322 Generic Signature Algorithm
// Written in 2021 by
//     Rajarshi Maitra <rajarshi149@protonmail.com>]
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # BIP322 Generic Signed Message Structure
//!
//! This module implements the BIP322 Generic Message Signer and Validator
//!
//! `https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki`
//!

use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::Builder;
use bitcoin::hashes::{
    borrow_slice_impl, hash160, hash_newtype, hex_fmt_impl, index_impl, ripemd160, serde_impl,
    sha256, sha256t_hash_newtype, Hash,
};
use bitcoin::psbt::PartiallySignedTransaction;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::sighash;
use bitcoin::{EcdsaSighashType, OutPoint, PublicKey, Transaction, TxIn, TxOut};

use super::hash256;
use super::interpreter::{Error as InterpreterError, Interpreter};
use crate::prelude::*;

// BIP322 message tagged hash midstate
const MIDSTATE: [u8; 32] = [
    137, 110, 101, 166, 158, 24, 33, 51, 154, 160, 217, 89, 167, 185, 222, 252, 115, 60, 186, 140,
    151, 47, 2, 20, 94, 72, 184, 111, 248, 59, 249, 156,
];

// BIP322 Tagged Hash
sha256t_hash_newtype!(
    MessageHash,
    MessageTag,
    MIDSTATE,
    64,
    doc = "BIP322 message tagged hash",
    false
);

/// BIP322 Error types
#[derive(Debug)]
pub enum BIP322Error {
    /// BIP322 Internal Error
    InternalError(String),

    /// Signature Validation Error
    ValidationError(InterpreterError),

    /// Signing Error
    MalformedSecrets,

    /// No addresses provided
    TooFewAddresses,

    /// Incorrect Message Hash
    InvalidMessage,
}

#[doc(hidden)]
impl From<InterpreterError> for BIP322Error {
    fn from(e: InterpreterError) -> BIP322Error {
        BIP322Error::ValidationError(e)
    }
}

/// Bip322 Signatures
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Bip322Signature {
    /// Legacy style. Only applicable for P2PKH message_challenge
    Legacy(Signature, PublicKey),

    /// Simple witness structure
    Simple(Vec<Vec<u8>>),

    /// Full `to_sign` transaction structure
    Full(Transaction),
}

/// TODO: BIP322 Signer structure
/// Update a Psbt with signatures required for signatures.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Bip322SignerSecrets {
    // Descriptor with secret keys
    desc: Vec<(String, Range<u32>)>, // Descriptor BIP32-keys
    // sha256 Preimages
    sha256_preimages: HashMap<sha256::Hash, [u8; 32]>,
    // hash256 preimages
    hash256_preimages: HashMap<hash256::Hash, [u8; 32]>,
    // ripemd160 preimages
    ripemd160_preimages: HashMap<ripemd160::Hash, [u8; 32]>,
    // hash160 preimages
    hash160_preimages: HashMap<hash160::Hash, [u8; 32]>,
}

/// Bip322 Signer that supports single and multiple Utxos
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Bip322Signer {
    /// Age
    pub age: u32,
    /// Height
    pub height: u32,
    /// Script pubkey -> Secrets
    pub spk_secrets_map: Bip322SignerSecrets,
}

impl Bip322Signer {
    /// Creates a signer for proving ownership of single funds
    pub fn new(
        age: u32,
        height: u32,
        spk_secrets_map: Bip322SignerSecrets,
    ) -> Result<Self, BIP322Error> {
        if spk_secrets_map.desc.is_empty() {
            return Err(BIP322Error::TooFewAddresses);
        }
        Ok(Bip322Signer {
            age,
            height,
            spk_secrets_map,
        })
    }
    // to_spend {msg_hash}  <- to_sign
    /// Sign the `to_sign` transaction with secret keys
    pub fn sign(&self, to_sign: &Transaction, msg: String) -> Result<Bip322Signature, BIP322Error> {
        // let desc = Descriptor::<DescriptorPublicKey>::from_str(self.spk_secrets_map.desc[0].0)?;
        // let script_pubkey = desc.script_pubkey();
        // let to_spend = create_to_spend(&msg, script_pubkey);

        // This `to_sign` transaction acts as the signature
        // 1. Set all the addresses as required

        // 2. Satisfy the addresses with

        // Ok(Bip322Signature::Full(to_sign))
        // let secp = Secp256k1::new();
        // let desc = Descriptor::parse_descriptor(&secp, self.spk_secrets_map.desc.0.0)?;
        // let script_pubkey = desc.0.script_pubkey();
        // let to_spend = create_to_spend(&msg, script_pubkey);

        // Satisfy the addresses here
        todo!()
    }

    pub fn create_psbt(&self, _msg: String) -> Result<(), ()> {
        todo!()
    }

    /// Look and infer the miniscript from txout/witness_script.
    ///
    /// # Returns:
    ///
    /// 1) Completed(Bip322Signature)
    /// 2) Insufficient information to finalize. Pass onto the next signer
    pub fn sign_psbt(
        &self,
        _psbt: &mut PartiallySignedTransaction,
        _msg: String,
    ) -> Result<(Bip322Signature, bool), BIP322Error> {
        todo!("Sanity checks that the descriptor correctly derives the address")

        // If the descriptor is BIP32 secret key, then we need to find the index corresponding to the wildcard
        // Substitute the index and get the concrete descriptor

        // Iterating over secrets (PublicKey -> SecretKey)
        // PsbtExt::sighash_msg => (Ecdsa(sighash::Message), Schnorr(sighash::Message))
        // 1) Ecdsa secp.sign_ecdsa
        // 2) Schnorr: Check if we know the internal key. sign_key_spend
        // 3) Schnorr script spend: sign_script_spend

        // Try finalize if possible
    }

    /// Create a BIP322Signature from the signing data
    pub fn finalize_psbt(
        &self,
        _psbt: &mut PartiallySignedTransaction,
        _msg: String,
    ) -> Result<Bip322Signature, ()> {
        todo!()
        //Full are the only valid outputs
    }
}

/// Create a `to_spend` transaction
pub(crate) fn create_to_spend(script_pubkey: bitcoin::Script, message: &String) -> Transaction {
    // create default input and output
    let mut vin = TxIn::default();
    let mut vout = TxOut::default();

    // calculate the message tagged hash
    let msg_hash = MessageHash::hash(message.as_bytes()).into_inner();

    // mutate the input with appropriate script_sig and sequence
    vin.script_sig = Builder::new()
        .push_int(0)
        .push_slice(&msg_hash[..])
        .into_script();
    vin.sequence = 0;

    // mutate the value and script_pubkey as appropriate
    vout.value = 0;
    vout.script_pubkey = script_pubkey.clone();

    // create and return final transaction
    Transaction {
        version: 0,
        lock_time: 0,
        input: vec![vin],
        output: vec![vout],
    }
}

/// Create to_sign transaction
/// This will create a transaction structure with empty signature and witness field
/// its up to the user of the library to fill the Tx with appropriate signature and witness
pub(crate) fn empty_to_sign(to_spend: &Transaction, age: u32, height: u32) -> Transaction {
    let outpoint = OutPoint::new(to_spend.txid(), 0);
    let mut input = TxIn::default();
    input.previous_output = outpoint;
    input.sequence = height;

    // create the output
    let output = TxOut {
        value: 0,
        script_pubkey: Builder::new()
            .push_opcode(opcodes::all::OP_RETURN)
            .into_script(),
    };

    // return resulting transaction
    Transaction {
        version: 2,
        lock_time: age,
        input: vec![input],
        output: vec![output],
    }
}

/// Validate a BIP322 Signature against the message and challenge script
/// Age: for the first input
/// Height: for the first input
/// * Outpoints could be fake.
/// * Can't check whether the funds are spent or not (no access to blockchain)
/// * txout: Set of addresses to prove control of
pub fn verify(
    txout: Vec<TxOut>,
    signature: Bip322Signature,
    message: String,
    age: u32,
    height: u32,
) -> Result<bool, BIP322Error> {
    // Atleast one address of prove control of should exist
    if txout.is_empty() {
        return Err(BIP322Error::TooFewAddresses);
    }
    let address = txout[0].script_pubkey.clone();
    // We should check that OutPoints are all different (no double spending, duh!)
    match &signature {
        // A Full signature can be validated directly against the `to_sign` transaction
        // How do we get `to_spend` here. RPC call?
        Bip322Signature::Full(to_sign) => {
            let to_spend = create_to_spend(address, &message);
            tx_verify(&to_spend, to_sign, message, txout)
        }

        // If Simple Signature is provided, the resulting `to_sign` Tx will be computed
        Bip322Signature::Simple(witness) => {
            let to_spend = create_to_spend(address, &message);
            let script_pubkey = &to_spend.output[0].script_pubkey;
            if !script_pubkey.is_witness_program() {
                return Err(BIP322Error::InternalError(
                    "Simple style signature is only applicable for Segwit type message_challenge"
                        .to_string(),
                ));
            } else {
                // create empty to_sign transaction
                let mut to_sign = empty_to_sign(&to_spend, age, height);
                to_sign.input[0].witness = bitcoin::Witness::from_vec(witness.to_owned());
                tx_verify(&to_spend, &to_sign, message, txout)
            }
        }

        // Legacy Signature can only be used to validate against P2PKH message_challenge
        Bip322Signature::Legacy(sig, pubkey) => {
            let to_spend = create_to_spend(address, &message);
            let script_pubkey = &to_spend.output[0].script_pubkey;
            if !script_pubkey.is_p2pkh() {
                return Err(BIP322Error::InternalError(
                    "Legacy style signature is only applicable for P2PKH message_challenge"
                        .to_string(),
                ));
            } else {
                let mut sig_ser = sig.serialize_der()[..].to_vec();
                sig_ser.push(EcdsaSighashType::All as u8);
                let script_sig = Builder::new()
                    .push_slice(&sig_ser[..])
                    .push_key(&pubkey)
                    .into_script();
                let mut to_sign = empty_to_sign(&to_spend, age, height);
                to_sign.input[0].script_sig = script_sig;
                tx_verify(&to_spend, &to_sign, message, txout)
            }
        }
    }
}

/// * Outpoints could be fake.
/// * Can't check whether the funds are spent or not (no access to blockchain)
fn tx_verify(
    to_spend: &Transaction,
    to_sign: &Transaction,
    msg: String,
    txout: Vec<TxOut>,
) -> Result<bool, BIP322Error> {
    let secp = Secp256k1::new();

    // BIP322 checks
    if to_sign.input[0].previous_output.txid != to_spend.txid() {
        return Err(BIP322Error::InternalError(
            "to_sign doesn't sign to_spend".to_string(),
        ));
    }
    if to_sign.input.is_empty() || to_sign.output.len() != 1 {
        return Err(BIP322Error::InternalError(
            "Improper transaction structure for to_sign".to_string(),
        ));
    }

    let script_pubkey = &to_spend.output[0].script_pubkey;
    let age = to_sign.input[0].sequence;
    let height = to_sign.lock_time;

    // Check against hash
    let msg_hash = MessageHash::hash(&msg.as_bytes()).into_inner();
    let expected_scriptsig = Builder::new()
        .push_int(0)
        .push_slice(&msg_hash[..])
        .into_script();

    if expected_scriptsig != to_spend.input[0].script_sig {
        return Err(BIP322Error::InvalidMessage);
    }

    // We can't argue about SEQUENCE_NUM are correct or not (no access to blockchain),
    // additional checks need to be taken care of.
    let interpreter = Interpreter::from_txdata(
        &script_pubkey,
        &to_sign.input[0].script_sig,
        &to_sign.input[0].witness,
        age,
        height,
    )?;

    // FIXME: Consider verification over all the inputs
    let prevouts = sighash::Prevouts::<TxOut>::All(&txout);

    let mut result = true;

    for idx in 0..txout.len() {
        for elem in interpreter.iter(&secp, &to_sign, idx, &prevouts) {
            match elem {
                Ok(_) => {}
                Err(e) => result = false,
            }
        }
    }

    Ok(result)
}

#[cfg(test)]
mod test {
    use bitcoin::hashes::sha256t::Tag;
    use bitcoin::hashes::{sha256, HashEngine};
    use bitcoin::secp256k1::{Message, Secp256k1};
    use bitcoin::{EcdsaSighashType, PrivateKey};

    use super::*;
    use crate::Descriptor;

    #[test]
    fn test_bip322_validation() {
        // Create key pairs and secp context
        let sk =
            PrivateKey::from_wif("cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy").unwrap();

        let ctx = Secp256k1::new();
        let pk = sk.public_key(&ctx);

        // wpkh descriptor from pubkey
        let desc = Descriptor::new_wpkh(pk).unwrap();

        // Corresponding p2pkh script. used for sighash calculation
        let p2pkh_script = bitcoin::Script::new_p2pkh(&pk.pubkey_hash());

        let message = "Hello World".to_string();
        let age = 0;
        let height = 0;

        // Create to_spend transaction
        let to_spend = {
            // create default input and output
            let mut vin = TxIn::default();
            let mut vout = TxOut::default();

            // calculate the message tagged hash
            let msg_hash = MessageHash::hash(message.as_bytes()).into_inner();

            // mutate the input with appropriate script_sig and sequence
            vin.script_sig = Builder::new()
                .push_int(0)
                .push_slice(&msg_hash[..])
                .into_script();
            vin.sequence = 0;

            // mutate the value and script_pubkey as appropriate
            vout.value = 0;
            vout.script_pubkey = desc.script_pubkey();

            // create and return final transaction
            Transaction {
                version: 0,
                lock_time: 0,
                input: vec![vin],
                output: vec![vout],
            }
        };

        // create an empty to_sign transaction
        let mut to_sign_empty = {
            // create the appropriate input
            let outpoint = OutPoint::new(to_spend.txid(), 0);
            let mut input = TxIn::default();
            input.previous_output = outpoint;
            input.sequence = height;

            // create the output
            let output = TxOut {
                value: 0,
                script_pubkey: Builder::new()
                    .push_opcode(opcodes::all::OP_RETURN)
                    .into_script(),
            };

            // return resulting transaction
            Transaction {
                version: 2,
                lock_time: age,
                input: vec![input],
                output: vec![output],
            }
        };

        // --------------------------------------------------------------
        // Check BIP322Signature::FUll

        // Generate witness for above wpkh pubkey
        let mut sighash_cache = bitcoin::util::sighash::SighashCache::new(&to_sign_empty);
        let message =
            sighash_cache.segwit_signature_hash(0, &p2pkh_script, 0, EcdsaSighashType::All);
        let message = Message::from_slice(&message.unwrap()).unwrap();

        let signature = ctx.sign_ecdsa(&message, &sk.inner);
        let der = signature.serialize_der();
        let mut sig_with_hash = der[..].to_vec();
        sig_with_hash.push(EcdsaSighashType::All as u8);

        let witness: Vec<Vec<u8>> = vec![sig_with_hash, pk.to_bytes()];
        to_sign_empty.input[0].witness = bitcoin::Witness::from_vec(witness.clone());

        let bip322_signature = Bip322Signature::Full(to_sign_empty);

        let expected_message = "Hello World".to_string();
        let expected_address = desc.script_pubkey();
        let expected_age = 0;
        let expected_height = 0;

        // Check validation
        assert!(verify(
            vec![TxOut {
                value: 0,
                script_pubkey: expected_address.clone()
            }],
            bip322_signature,
            expected_message.clone(),
            expected_age,
            expected_height
        )
        .unwrap());

        // ------------------------------------------------------------
        // Check Bip322Signature::Simple

        assert!(verify(
            vec![TxOut {
                value: 0,
                script_pubkey: expected_address
            }],
            Bip322Signature::Simple(witness),
            expected_message.clone(),
            expected_age,
            expected_height
        )
        .unwrap());

        // ------------------------------------------------------------
        // Check Bip322Signature::Legacy

        let desc = Descriptor::new_pkh(pk);

        // Replace previous message_challenge with p2pkh
        let address = desc.script_pubkey();
        let to_spend = create_to_spend(address.clone(), &expected_message);

        let to_sign = empty_to_sign(&to_spend, expected_age, expected_height);

        let message =
            to_sign.signature_hash(0, &desc.script_pubkey(), EcdsaSighashType::All as u32);
        let message = Message::from_slice(&message[..]).unwrap();
        let signature = ctx.sign_ecdsa(&message, &sk.inner);

        // Create Bip322Signature::Legacy
        let bip322_sig = Bip322Signature::Legacy(signature, pk);

        assert!(verify(
            vec![TxOut {
                value: 0,
                script_pubkey: address
            }],
            bip322_sig,
            expected_message,
            expected_age,
            expected_height
        )
        .unwrap());
    }

    #[test]
    fn test_tagged_hash() {
        let mut engine = sha256::Hash::engine();
        let tag_hash = sha256::Hash::hash("BIP0322-signed-message".as_bytes());
        engine.input(&tag_hash[..]);
        engine.input(&tag_hash[..]);

        assert_eq!(engine.midstate().into_inner(), MIDSTATE);
        assert_eq!(engine.midstate(), MessageTag::engine().midstate());
    }
}
