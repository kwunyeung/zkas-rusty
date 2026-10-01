use orchard::primitives::redpallas::{Signature, SpendAuth, VerificationKey};
use serde_json::Value;
use zkas_browser_signer::PrivateAccountSigner;
use zkas_sdk::{Network, PreparedPaymentMultiEnvelope};

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/v3-payment.json")).unwrap()
}

fn new_signer(data: &Value, genesis: &str) -> PrivateAccountSigner {
    let mut seed = hex::decode(data["accountSeedHex"].as_str().unwrap()).unwrap();
    let signer = PrivateAccountSigner::new(&mut seed, "mainnet", genesis, &data["approvedIntent"].to_string()).unwrap();
    assert_eq!(seed, [0; 32]);
    signer
}

fn changed_envelope(data: &Value, mutate: impl FnOnce(&mut zkas_sdk::PreparedPaymentMulti)) -> String {
    let wire: PreparedPaymentMultiEnvelope = serde_json::from_value(data["preparedEnvelope"].clone()).unwrap();
    let mut typed = wire.to_typed().unwrap();
    mutate(&mut typed);
    serde_json::to_string(&PreparedPaymentMultiEnvelope::from_typed(&typed, &Network::Mainnet).unwrap()).unwrap()
}

#[test]
fn real_prepared_payment_signatures_verify_under_bundle_action_keys() {
    let data = fixture();
    let signer = new_signer(&data, data["genesisHex"].as_str().unwrap());
    let wire: PreparedPaymentMultiEnvelope = serde_json::from_value(data["preparedEnvelope"].clone()).unwrap();
    let typed = wire.to_typed().unwrap();
    let signatures: Vec<Value> =
        serde_json::from_str(&signer.sign_prepared_v3(&data["preparedEnvelope"].to_string()).unwrap()).unwrap();
    assert_eq!(signatures.len(), typed.spend_auth.len());
    let sighash = kaspa_shielded_core::verify::sighash(&typed.bundle, &typed.network_domain, &typed.tx_context);
    for signature in signatures {
        let index = signature["actionIndex"].as_u64().unwrap() as usize;
        let bytes: [u8; 64] = hex::decode(signature["signatureHex"].as_str().unwrap()).unwrap().try_into().unwrap();
        let key = VerificationKey::<SpendAuth>::try_from(typed.bundle.actions[index].rk).unwrap();
        key.verify(&sighash, &Signature::<SpendAuth>::from(bytes)).unwrap();
    }
}

#[test]
fn signer_rejects_wrong_network_context_fee_memo_action_key_and_missing_spend() {
    let data = fixture();
    let signer = new_signer(&data, data["genesisHex"].as_str().unwrap());
    let wrong_genesis = new_signer(&data, &"56".repeat(32));
    assert!(wrong_genesis.sign_prepared_v3(&data["preparedEnvelope"].to_string()).is_err());
    let mut seed = hex::decode(data["accountSeedHex"].as_str().unwrap()).unwrap();
    assert!(
        PrivateAccountSigner::new(&mut seed, "testnet", data["genesisHex"].as_str().unwrap(), &data["approvedIntent"].to_string())
            .is_err()
    );
    assert_eq!(seed, [0; 32]);

    let wrong_account = changed_envelope(&data, |payment| payment.claimed_account = payment.claimed_outputs[0].recipient);
    assert!(signer.sign_prepared_v3(&wrong_account).is_err());
    let wrong_context = changed_envelope(&data, |payment| payment.tx_context[1] ^= 1);
    assert!(signer.sign_prepared_v3(&wrong_context).is_err());
    let wrong_fee = changed_envelope(&data, |payment| {
        payment.bundle.value_balance = 3_000_001;
        payment.claimed_fee = 3_000_001;
    });
    assert!(signer.sign_prepared_v3(&wrong_fee).is_err());
    let wrong_memo = changed_envelope(&data, |payment| payment.claimed_outputs[0].memo[0] ^= 1);
    assert!(signer.sign_prepared_v3(&wrong_memo).is_err());
    let wrong_action_key = changed_envelope(&data, |payment| payment.spend_auth[0].alpha[0] ^= 1);
    assert!(signer.sign_prepared_v3(&wrong_action_key).is_err());
    let missing_spend = changed_envelope(&data, |payment| payment.spend_auth.clear());
    assert!(signer.sign_prepared_v3(&missing_spend).is_err());
}

#[test]
fn signer_bounds_json_and_rejects_malformed_or_modified_checksum() {
    let data = fixture();
    let signer = new_signer(&data, data["genesisHex"].as_str().unwrap());
    assert!(signer.sign_prepared_v3("{").is_err());
    assert!(signer.sign_prepared_v3(&"x".repeat(512 * 1024 + 1)).is_err());
    let mut corrupt = data["preparedEnvelope"].clone();
    corrupt["outputs"][0]["memo"] = Value::String("00".repeat(512));
    assert!(signer.sign_prepared_v3(&corrupt.to_string()).is_err());
    let mut too_many = data["approvedIntent"].clone();
    let output = too_many["outputs"][0].clone();
    too_many["outputs"] = Value::Array(vec![output; zkas_wallet_engine::max_payees_per_tx() + 1]);
    let mut seed = hex::decode(data["accountSeedHex"].as_str().unwrap()).unwrap();
    assert!(PrivateAccountSigner::new(&mut seed, "mainnet", data["genesisHex"].as_str().unwrap(), &too_many.to_string()).is_err());
    assert_eq!(seed, [0; 32]);
}
