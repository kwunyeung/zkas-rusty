//! Adapt the public dummy finalized fixture to signatures from one browser handle.

use kaspa_consensus_core::tx::Transaction;
use kaspa_shielded_core::{
    bundle::ShieldedBundle,
    verify::{sighash, verify_bundle},
};
use kaspa_shielded_wallet::tx::payment_tx;
use serde_json::Value;
use zkas_sdk::PreparedPaymentMultiEnvelope;

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let signatures: Vec<Value> = serde_json::from_str(args.get(1).expect("signatures JSON")).unwrap();
    let mode = args.get(2).map(String::as_str).unwrap_or("valid");
    let fixture: Value = serde_json::from_str(include_str!("../tests/fixtures/v3-finalized.json")).unwrap();
    let envelope: PreparedPaymentMultiEnvelope = serde_json::from_value(fixture["preparedEnvelope"].clone()).unwrap();
    let prepared = envelope.to_typed().unwrap();
    let raw = hex::decode(fixture["transactionHex"].as_str().unwrap()).unwrap();
    let tx: Transaction = borsh::from_slice(&raw).unwrap();
    let mut bundle = ShieldedBundle::from_bytes(&tx.payload).unwrap();
    assert_eq!(signatures.len(), prepared.spend_auth.len());
    for (signature, request) in signatures.iter().zip(&prepared.spend_auth) {
        let index = signature["actionIndex"].as_u64().unwrap() as usize;
        assert_eq!(index, request.action_index);
        bundle.actions[index].spend_auth_sig = hex::decode(signature["signatureHex"].as_str().unwrap()).unwrap().try_into().unwrap();
    }
    let mut tx = payment_tx(bundle.to_bytes());
    let verified = ShieldedBundle::from_bytes(&tx.payload).unwrap();
    verify_bundle(&verified, &sighash(&verified, &prepared.network_domain, &prepared.tx_context)).unwrap();
    match mode {
        "valid" => {}
        "proof" => bundle.proof[0] ^= 1,
        "spend" => bundle.actions[0].spend_auth_sig[0] ^= 1,
        "binding" => bundle.binding_sig[0] ^= 1,
        "effect" => bundle.actions[0].out_ciphertext[0] ^= 1,
        "version" => tx.version = 3,
        "mass" => tx.set_storage_mass(1),
        "cached-id" => {}
        "trailing" => {}
        "payload-length" => {}
        _ => panic!("unsupported fixture mutation"),
    }
    if matches!(mode, "proof" | "spend" | "binding" | "effect") {
        tx = payment_tx(bundle.to_bytes());
    }
    if mode == "version" {
        tx.finalize();
    }
    let mut bytes = borsh::to_vec(&tx).unwrap();
    if mode == "cached-id" {
        *bytes.last_mut().unwrap() ^= 1;
    }
    if mode == "trailing" {
        bytes.push(0);
    }
    if mode == "payload-length" {
        bytes[46] ^= 1;
    }
    println!("{}", hex::encode(bytes));
}
