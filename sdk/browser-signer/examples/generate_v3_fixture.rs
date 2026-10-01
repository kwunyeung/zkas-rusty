//! Generate an unsigned payment envelope from public test-only wallet vectors.

use incrementalmerkletree::{Hashable, Level};
use kaspa_shielded_core::{payment_check::PaymentOutputIntent, wallet::prepare_payment_multi};
use orchard::{
    keys::{FullViewingKey, Scope},
    note::{Note, NoteVersion, RandomSeed, Rho},
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
};
use zkas_sdk::{Network, NetworkConfig, PreparedPaymentMultiEnvelope, ShieldedAddress, SoftwareSigner};
use zkas_signer::{PAYMENT_TX_CONTEXT, PreparedPaymentMulti, SpendAuthRequest};

fn changed_envelope(base: &PreparedPaymentMulti, mutate: impl FnOnce(&mut PreparedPaymentMulti)) -> PreparedPaymentMultiEnvelope {
    let mut changed = base.clone();
    mutate(&mut changed);
    PreparedPaymentMultiEnvelope::from_typed(&changed, &Network::Mainnet).unwrap()
}

fn small_field(first: u8) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[0] = first;
    bytes
}

fn main() {
    let account_seed: [u8; 32] =
        hex::decode("20468ca002014b860fce6926a03c8eeaceebb48b365160f60836cc3a111d3b38").unwrap().try_into().unwrap();
    let recipient_seed: [u8; 32] =
        hex::decode("fa502dd864b61baccb7eb86cd30d2eeef6a39ab32ef09b415054ea8a2c157c32").unwrap().try_into().unwrap();
    let signer = SoftwareSigner::new(account_seed).unwrap();
    let recipient = SoftwareSigner::new(recipient_seed).unwrap();
    let fvk = FullViewingKey::from_bytes(&signer.full_viewing_key()).unwrap();
    let rho = Option::<Rho>::from(Rho::from_bytes(&small_field(3))).unwrap();
    let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(small_field(4), &rho)).unwrap();
    let note = Option::<Note>::from(Note::from_parts(
        fvk.address_at(0u32, Scope::External),
        NoteValue::from_raw(10_000_000),
        rho,
        rseed,
        NoteVersion::V2,
    ))
    .unwrap();
    let path = MerklePath::from_parts(0, core::array::from_fn(|i| <MerkleHashOrchard as Hashable>::empty_root(Level::from(i as u8))));
    let mut memo = [0; 512];
    memo[..15].copy_from_slice(b"browser fixture");
    let outputs = vec![PaymentOutputIntent { recipient: recipient.address_bytes(), amount: 2_000_000, memo }];
    let genesis = NetworkConfig::MAINNET_GENESIS;
    let payment = prepare_payment_multi(&fvk, vec![(note, path)], &outputs, 3_000_000, &genesis, &PAYMENT_TX_CONTEXT, true).unwrap();
    let prepared = PreparedPaymentMulti {
        version: PreparedPaymentMulti::VERSION,
        network_domain: genesis,
        tx_context: PAYMENT_TX_CONTEXT.to_vec(),
        bundle: payment.effects,
        disclosure: payment.disclosure,
        spend_auth: payment
            .spend_auth_requests
            .into_iter()
            .map(|(action_index, alpha)| SpendAuthRequest { action_index, alpha })
            .collect(),
        claimed_account: signer.address_bytes(),
        claimed_outputs: outputs.clone(),
        claimed_fee: 3_000_000,
    };
    let rejected = serde_json::json!({
        "wrongAccount": changed_envelope(&prepared, |p| p.claimed_account = recipient.address_bytes()),
        "wrongContext": changed_envelope(&prepared, |p| p.tx_context[1] ^= 1),
        "wrongFee": changed_envelope(&prepared, |p| { p.bundle.value_balance += 1; p.claimed_fee += 1; }),
        "wrongMemo": changed_envelope(&prepared, |p| p.claimed_outputs[0].memo[0] ^= 1),
        "wrongActionKey": changed_envelope(&prepared, |p| p.spend_auth[0].alpha[0] ^= 1),
        "missingSpend": changed_envelope(&prepared, |p| p.spend_auth.clear()),
    });
    let envelope = PreparedPaymentMultiEnvelope::from_typed(&prepared, &Network::Mainnet).unwrap();
    let account = ShieldedAddress::from_raw(&Network::Mainnet, signer.address_bytes()).unwrap().to_string();
    let recipient = ShieldedAddress::from_raw(&Network::Mainnet, recipient.address_bytes()).unwrap().to_string();
    let approved = serde_json::json!({
        "account": account,
        "outputs": [{"recipient": recipient, "amountSompi": "2000000", "memoHex": hex::encode(memo)}],
        "maxFeeSompi": "3000000"
    });
    println!(
        "{}",
        serde_json::json!({
            "accountSeedHex": hex::encode(account_seed),
            "network": "mainnet",
            "genesisHex": hex::encode(genesis),
            "approvedIntent": approved,
            "preparedEnvelope": envelope,
            "rejectedEnvelopes": rejected,
        })
    );
}
