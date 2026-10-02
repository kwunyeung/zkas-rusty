use orchard::primitives::redpallas::{Signature, SpendAuth, VerificationKey};
use serde_json::Value;
use sha2::Digest;
use zkas_browser_signer::PrivateAccountSigner;
use zkas_sdk::{Network, PreparedPaymentMultiEnvelope};

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/v3-payment.json")).unwrap()
}

fn new_signer(data: &Value, genesis: &str) -> PrivateAccountSigner {
    let seed_hex = data["accountSeedHex"].as_str().or_else(|| data["provenance"]["accountSeedHex"].as_str()).unwrap();
    let mut seed = hex::decode(seed_hex).unwrap();
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
    let mut signer = new_signer(&data, data["genesisHex"].as_str().unwrap());
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
    let mut signer = new_signer(&data, data["genesisHex"].as_str().unwrap());
    let mut wrong_genesis = new_signer(&data, &"56".repeat(32));
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
    let mut signer = new_signer(&data, data["genesisHex"].as_str().unwrap());
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

fn finalized_fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/v3-finalized.json")).unwrap()
}

fn finalized_for_signatures(data: &Value, signatures: &[Value]) -> String {
    use kaspa_consensus_core::tx::Transaction;
    let raw = hex::decode(data["transactionHex"].as_str().unwrap()).unwrap();
    let tx: Transaction = borsh::from_slice(&raw).unwrap();
    let mut bundle = kaspa_shielded_core::bundle::ShieldedBundle::from_bytes(&tx.payload).unwrap();
    for signature in signatures {
        let index = signature["actionIndex"].as_u64().unwrap() as usize;
        bundle.actions[index].spend_auth_sig = hex::decode(signature["signatureHex"].as_str().unwrap()).unwrap().try_into().unwrap();
    }
    let tx = kaspa_shielded_wallet::tx::payment_tx(bundle.to_bytes());
    hex::encode(borsh::to_vec(&tx).unwrap())
}

#[test]
fn finalized_v3_requires_exact_prepared_handle_and_actual_signatures() {
    let data = finalized_fixture();
    let mut signer = new_signer(&data, data["genesisHex"].as_str().unwrap());
    assert!(signer.verify_finalized_v3(data["transactionHex"].as_str().unwrap()).is_err());
    let prepared = data["preparedEnvelope"].to_string();
    let signed = signer.sign_prepared_v3(&prepared).unwrap();
    assert_eq!(signer.sign_prepared_v3(&prepared).unwrap(), signed);
    let other_prepared = fixture()["preparedEnvelope"].to_string();
    assert!(signer.sign_prepared_v3(&other_prepared).is_err());
    let signatures: Vec<Value> = serde_json::from_str(&signed).unwrap();
    let exact = finalized_for_signatures(&data, &signatures);
    let result: Value = serde_json::from_str(&signer.verify_finalized_v3(&exact).unwrap()).unwrap();
    assert_eq!(result["transactionHex"], exact);
    let bytes = hex::decode(exact).unwrap();
    let tx: kaspa_consensus_core::tx::Transaction = borsh::from_slice(&bytes).unwrap();
    assert_eq!(result["txid"], hex::encode(tx.id().as_bytes()));
    assert_eq!(result["sha256"], hex::encode(sha2::Sha256::digest(&bytes)));
}

#[test]
fn private_signed_ticket_restores_original_signatures_and_full_finalized_verifier() {
    let data = finalized_fixture();
    let prepared = data["preparedEnvelope"].to_string();
    let mut original = new_signer(&data, data["genesisHex"].as_str().unwrap());
    assert!(original.export_signed_v3_ticket().is_err());
    let original_signatures = original.sign_prepared_v3(&prepared).unwrap();
    let ticket = original.export_signed_v3_ticket().unwrap();
    assert!(!ticket.contains(data["provenance"]["accountSeedHex"].as_str().unwrap()));
    let signatures: Vec<Value> = serde_json::from_str(&original_signatures).unwrap();
    let exact = finalized_for_signatures(&data, &signatures);

    let mut restored = new_signer(&data, data["genesisHex"].as_str().unwrap());
    assert!(restored.verify_finalized_v3(&exact).is_err());
    restored.import_signed_v3_ticket(&ticket).unwrap();
    assert_eq!(restored.sign_prepared_v3(&prepared).unwrap(), original_signatures);
    assert!(restored.sign_prepared_v3(&fixture()["preparedEnvelope"].to_string()).is_err());
    let recovered: Value = serde_json::from_str(&restored.verify_finalized_v3(&exact).unwrap()).unwrap();
    assert_eq!(recovered["transactionHex"], exact);
    assert_eq!(restored.export_signed_v3_ticket().unwrap(), ticket);
    assert!(restored.verify_finalized_v3(data["transactionHex"].as_str().unwrap()).is_err());
    assert!(restored.import_signed_v3_ticket(&ticket).is_err());
}

#[test]
fn private_signed_ticket_rejects_changed_context_partial_or_invalid_signature_map() {
    let data = finalized_fixture();
    let mut original = new_signer(&data, data["genesisHex"].as_str().unwrap());
    let original_signatures = original.sign_prepared_v3(&data["preparedEnvelope"].to_string()).unwrap();
    let ticket = original.export_signed_v3_ticket().unwrap();

    let mut wrong_genesis = new_signer(&data, &"56".repeat(32));
    assert!(wrong_genesis.import_signed_v3_ticket(&ticket).is_err());
    let mut wrong_approval = data.clone();
    wrong_approval["approvedIntent"]["maxFeeSompi"] = Value::String("2999999".into());
    let mut wrong_approval = new_signer(&wrong_approval, data["genesisHex"].as_str().unwrap());
    assert!(wrong_approval.import_signed_v3_ticket(&ticket).is_err());
    let mut wider_approval = data.clone();
    wider_approval["approvedIntent"]["maxFeeSompi"] = Value::String("4000000".into());
    let mut wider_approval = new_signer(&wider_approval, data["genesisHex"].as_str().unwrap());
    assert!(wider_approval.import_signed_v3_ticket(&ticket).is_err());

    let signatures: Vec<Value> = serde_json::from_str(&original_signatures).unwrap();
    let signature_hex = signatures[0]["signatureHex"].as_str().unwrap();
    let mut invalid = signature_hex.to_string();
    invalid.replace_range(0..2, if &invalid[..2] == "00" { "01" } else { "00" });
    let changed = ticket.replacen(signature_hex, &invalid, 1);
    let mut restored = new_signer(&data, data["genesisHex"].as_str().unwrap());
    assert!(restored.import_signed_v3_ticket(&changed).is_err());
    assert!(restored.verify_finalized_v3(data["transactionHex"].as_str().unwrap()).is_err());

    let mut partial: Value = serde_json::from_str(&ticket).unwrap();
    partial["signatures"] = Value::Array(vec![]);
    assert!(new_signer(&data, data["genesisHex"].as_str().unwrap()).import_signed_v3_ticket(&partial.to_string()).is_err());
    let mut duplicated: Value = serde_json::from_str(&ticket).unwrap();
    duplicated["signatures"] = Value::Array(vec![signatures[0].clone(), signatures[0].clone()]);
    assert!(new_signer(&data, data["genesisHex"].as_str().unwrap()).import_signed_v3_ticket(&duplicated.to_string()).is_err());
    let mut unknown: Value = serde_json::from_str(&ticket).unwrap();
    unknown["seed"] = Value::String("not allowed".into());
    assert!(new_signer(&data, data["genesisHex"].as_str().unwrap()).import_signed_v3_ticket(&unknown.to_string()).is_err());
    let mut unknown_nested: Value = serde_json::from_str(&ticket).unwrap();
    unknown_nested["prepared"]["unapproved"] = Value::Bool(true);
    assert!(new_signer(&data, data["genesisHex"].as_str().unwrap()).import_signed_v3_ticket(&unknown_nested.to_string()).is_err());
    let duplicated_field = ticket.replacen("\"version\":1,", "\"version\":1,\"version\":1,", 1);
    assert!(new_signer(&data, data["genesisHex"].as_str().unwrap()).import_signed_v3_ticket(&duplicated_field).is_err());
    let mut wrong_version: Value = serde_json::from_str(&ticket).unwrap();
    wrong_version["version"] = Value::from(2);
    assert!(new_signer(&data, data["genesisHex"].as_str().unwrap()).import_signed_v3_ticket(&wrong_version.to_string()).is_err());
    let mut wrong_format: Value = serde_json::from_str(&ticket).unwrap();
    wrong_format["format"] = Value::String("unknown".into());
    assert!(new_signer(&data, data["genesisHex"].as_str().unwrap()).import_signed_v3_ticket(&wrong_format.to_string()).is_err());
    let mut wrong_digest: Value = serde_json::from_str(&ticket).unwrap();
    wrong_digest["approvalDigest"] = Value::String("00".repeat(32));
    assert!(new_signer(&data, data["genesisHex"].as_str().unwrap()).import_signed_v3_ticket(&wrong_digest.to_string()).is_err());
    let noncanonical = ticket.replace("\"version\":1,", "\"version\": 1,");
    assert!(new_signer(&data, data["genesisHex"].as_str().unwrap()).import_signed_v3_ticket(&noncanonical).is_err());
    let mut already_signed = new_signer(&data, data["genesisHex"].as_str().unwrap());
    already_signed.sign_prepared_v3(&data["preparedEnvelope"].to_string()).unwrap();
    assert!(already_signed.import_signed_v3_ticket(&ticket).is_err());
    assert!(new_signer(&data, data["genesisHex"].as_str().unwrap()).import_signed_v3_ticket(&"x".repeat(640 * 1024 + 1)).is_err());
}

#[test]
fn finalized_v3_rejects_corrupted_proof_authorizations_and_borsh_shape() {
    use kaspa_consensus_core::tx::Transaction;
    let data = finalized_fixture();
    let mut signer = new_signer(&data, data["genesisHex"].as_str().unwrap());
    let signed = signer.sign_prepared_v3(&data["preparedEnvelope"].to_string()).unwrap();
    let signatures: Vec<Value> = serde_json::from_str(&signed).unwrap();
    let exact = finalized_for_signatures(&data, &signatures);
    let bytes = hex::decode(&exact).unwrap();
    let tx: Transaction = borsh::from_slice(&bytes).unwrap();
    for kind in 0..4 {
        let mut bundle = kaspa_shielded_core::bundle::ShieldedBundle::from_bytes(&tx.payload).unwrap();
        match kind {
            0 => bundle.proof[0] ^= 1,
            1 => bundle.actions[0].spend_auth_sig[0] ^= 1,
            2 => bundle.binding_sig[0] ^= 1,
            _ => bundle.actions[0].out_ciphertext[0] ^= 1,
        }
        let changed = kaspa_shielded_wallet::tx::payment_tx(bundle.to_bytes());
        assert!(signer.verify_finalized_v3(&hex::encode(borsh::to_vec(&changed).unwrap())).is_err());
    }
    let mut cached_id = bytes.clone();
    *cached_id.last_mut().unwrap() ^= 1;
    assert!(signer.verify_finalized_v3(&hex::encode(cached_id)).is_err());
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(signer.verify_finalized_v3(&hex::encode(extra)).is_err());
    let mut wrong_version = tx.clone();
    wrong_version.version = 3;
    wrong_version.finalize();
    assert!(signer.verify_finalized_v3(&hex::encode(borsh::to_vec(&wrong_version).unwrap())).is_err());
    let mut wrong_mass = tx.clone();
    wrong_mass.set_storage_mass(1);
    wrong_mass.finalize();
    assert!(signer.verify_finalized_v3(&hex::encode(borsh::to_vec(&wrong_mass).unwrap())).is_err());
}
