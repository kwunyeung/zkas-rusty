use zkas_browser_signer::PrivateAccountSigner;

const ACCOUNT_SEED: &str = "20468ca002014b860fce6926a03c8eeaceebb48b365160f60836cc3a111d3b38";
const OTHER_SEED: &str = "fa502dd864b61baccb7eb86cd30d2eeef6a39ab32ef09b415054ea8a2c157c32";
const ACCOUNT_ADDRESS: &str = "zkas:px8dx79gspafw49lw989mzdxhlqt6pehw9ql54r8ayyymv59vday3mtyxm432g4t6we2gygp3udqluy";
const OTHER_ADDRESS: &str = "zkas:p8vmwuwk2npzsjc4udm4zurtdpd76rwyqwma3j9fdda3lc4yhsp30tcesf54ehq29t66jysxg9mc25s";

fn approved(account: &str, recipient: &str, amount: &str, memo_hex: &str) -> String {
    serde_json::json!({
        "account": account,
        "outputs": [{"recipient": recipient, "amountSompi": amount, "memoHex": memo_hex}],
        "maxFeeSompi": "3000000"
    })
    .to_string()
}

#[test]
fn wallet_private_constructor_wipes_seed_and_uses_legacy_account_vector() {
    let mut seed = hex::decode(ACCOUNT_SEED).unwrap();
    let intent = approved(ACCOUNT_ADDRESS, OTHER_ADDRESS, "1", &"00".repeat(512));
    let signer = PrivateAccountSigner::new(&mut seed, "mainnet", &"55".repeat(32), &intent).unwrap();
    assert_eq!(seed, [0; 32]);
    assert_eq!(signer.approved_account(), ACCOUNT_ADDRESS);
    let other_seed: [u8; 32] = hex::decode(OTHER_SEED).unwrap().try_into().unwrap();
    let other = zkas_sdk::SoftwareSigner::new(other_seed).unwrap();
    let other_address = zkas_sdk::ShieldedAddress::from_raw(&zkas_sdk::Network::Mainnet, other.address_bytes()).unwrap();
    assert_eq!(other_address.to_string(), OTHER_ADDRESS);
}

#[test]
fn approval_rejects_noncanonical_values_and_foreign_account() {
    let base = hex::decode(ACCOUNT_SEED).unwrap();
    let make = |account, recipient, amount, memo: String| {
        let mut seed = base.clone();
        let result = PrivateAccountSigner::new(&mut seed, "mainnet", &"55".repeat(32), &approved(account, recipient, amount, &memo));
        assert_eq!(seed, [0; 32]);
        result
    };
    assert!(make(OTHER_ADDRESS, OTHER_ADDRESS, "1", "00".repeat(512)).is_err());
    assert!(make(ACCOUNT_ADDRESS, OTHER_ADDRESS, "01", "00".repeat(512)).is_err());
    assert!(make(ACCOUNT_ADDRESS, OTHER_ADDRESS, "1", "AA".repeat(512)).is_err());
    assert!(make(ACCOUNT_ADDRESS, OTHER_ADDRESS, "1", "00".repeat(511)).is_err());
    assert!(make(ACCOUNT_ADDRESS, &OTHER_ADDRESS.to_ascii_uppercase(), "1", "00".repeat(512)).is_err());
}
