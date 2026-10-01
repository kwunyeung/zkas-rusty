//! Verify the browser runtime's signatures against the fixture's action keys.

use orchard::primitives::redpallas::{Signature, SpendAuth, VerificationKey};
use serde_json::Value;
use zkas_sdk::PreparedPaymentMultiEnvelope;

fn main() {
    let path = std::env::args().nth(1).expect("signatures JSON path");
    let fixture: Value = serde_json::from_str(include_str!("../tests/fixtures/v3-payment.json")).unwrap();
    let envelope: PreparedPaymentMultiEnvelope = serde_json::from_value(fixture["preparedEnvelope"].clone()).unwrap();
    let typed = envelope.to_typed().unwrap();
    let signatures: Vec<Value> = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(signatures.len(), typed.spend_auth.len());
    let sighash = kaspa_shielded_core::verify::sighash(&typed.bundle, &typed.network_domain, &typed.tx_context);
    for signature in signatures {
        let index = signature["actionIndex"].as_u64().unwrap() as usize;
        let bytes: [u8; 64] = hex::decode(signature["signatureHex"].as_str().unwrap()).unwrap().try_into().unwrap();
        let key = VerificationKey::<SpendAuth>::try_from(typed.bundle.actions[index].rk).unwrap();
        key.verify(&sighash, &Signature::<SpendAuth>::from(bytes)).unwrap();
    }
    println!("browser signer signatures verified against prepared action keys");
}
