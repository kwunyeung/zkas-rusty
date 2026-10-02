//! Byte-exact wallet-side recovery of outputs from a complete Orchard bundle.
//!
//! This module only decrypts. The caller must independently establish the full
//! transaction's ID, accepted selected-chain provenance, and bundle validity.
//! A receiver learns its own output, not the contents of other encrypted outputs.

use orchard::{
    Address,
    keys::{FullViewingKey, Scope},
    note::{ExtractedNoteCommitment, Note},
    note_encryption::OrchardDomain,
};
use zcash_note_encryption::{try_note_decryption, try_output_recovery_with_ovk};

/// An output recoverable through the account's incoming or outgoing viewing key.
pub struct FullMemoOutput {
    pub action_index: usize,
    pub recipient: [u8; 43],
    pub value: u64,
    pub memo: [u8; 512],
    pub incoming_scopes: Vec<ViewingScope>,
    pub outgoing_scopes: Vec<ViewingScope>,
    /// External account address index when it is one of the first five.
    pub external_index: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViewingScope {
    External,
    Internal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FullMemoError {
    BundleTooLarge,
    MalformedBundle,
    MalformedAction(usize),
    ConflictingRecovery(usize),
}

const MAX_FULL_MEMO_BUNDLE_BYTES: usize = 500_000;

type OpenedNote = (Note, Address, [u8; 512]);

fn merge_recovery(slot: &mut Option<OpenedNote>, candidate: OpenedNote, index: usize) -> Result<(), FullMemoError> {
    if let Some((note, address, memo)) = slot {
        if ExtractedNoteCommitment::from(note.commitment()).to_bytes()
            != ExtractedNoteCommitment::from(candidate.0.commitment()).to_bytes()
            || address.to_raw_address_bytes() != candidate.1.to_raw_address_bytes()
            || note.value().inner() != candidate.0.value().inner()
            || *memo != candidate.2
        {
            return Err(FullMemoError::ConflictingRecovery(index));
        }
    } else {
        *slot = Some(candidate);
    }
    Ok(())
}

/// Decrypt every account-readable output, keeping its exact padded memo field.
pub fn recover_full_outputs(fvk: &FullViewingKey, bundle_bytes: &[u8]) -> Result<Vec<FullMemoOutput>, FullMemoError> {
    if bundle_bytes.len() > MAX_FULL_MEMO_BUNDLE_BYTES {
        return Err(FullMemoError::BundleTooLarge);
    }
    let bundle = crate::bundle::ShieldedBundle::from_bytes(bundle_bytes).map_err(|_| FullMemoError::MalformedBundle)?;
    if bundle.to_bytes() != bundle_bytes {
        return Err(FullMemoError::MalformedBundle);
    }
    let ivks = [
        (ViewingScope::External, fvk.to_ivk(Scope::External).prepare()),
        (ViewingScope::Internal, fvk.to_ivk(Scope::Internal).prepare()),
    ];
    let ovks = [(ViewingScope::External, fvk.to_ovk(Scope::External)), (ViewingScope::Internal, fvk.to_ovk(Scope::Internal))];
    let known_addresses: [[u8; 43]; 5] = core::array::from_fn(|i| fvk.address_at(i as u32, Scope::External).to_raw_address_bytes());
    let mut outputs = Vec::new();
    for (index, wire) in bundle.actions.iter().enumerate() {
        let action = crate::wallet::scan::reconstruct_action(wire).ok_or(FullMemoError::MalformedAction(index))?;
        let domain = OrchardDomain::for_action(&action);
        let mut opened = None;
        let mut incoming_scopes = Vec::new();
        let mut outgoing_scopes = Vec::new();
        for (scope, ivk) in &ivks {
            if let Some(candidate) = try_note_decryption(&domain, ivk, &action) {
                merge_recovery(&mut opened, candidate, index)?;
                incoming_scopes.push(*scope);
            }
        }
        for (scope, ovk) in &ovks {
            if let Some(candidate) = try_output_recovery_with_ovk(&domain, ovk, &action, action.cv_net(), &wire.out_ciphertext) {
                merge_recovery(&mut opened, candidate, index)?;
                outgoing_scopes.push(*scope);
            }
        }
        let Some((note, recipient, memo)) = opened else { continue };
        let recipient = recipient.to_raw_address_bytes();
        let external_index = known_addresses.iter().position(|address| *address == recipient).map(|i| i as u32);
        outputs.push(FullMemoOutput {
            action_index: index,
            recipient,
            value: note.value().inner(),
            memo,
            incoming_scopes,
            outgoing_scopes,
            external_index,
        });
    }
    Ok(outputs)
}

#[cfg(all(test, feature = "circuit"))]
mod tests {
    use super::*;
    use crate::{payment_check::PaymentOutputIntent, wallet::prepare_payment_multi};
    use incrementalmerkletree::{Hashable, Level};
    use orchard::{
        keys::{Scope, SpendingKey},
        note::{Note, NoteVersion, RandomSeed, Rho},
        tree::{MerkleHashOrchard, MerklePath},
        value::NoteValue,
    };

    fn fvk(seed: [u8; 32]) -> FullViewingKey {
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(seed)).unwrap();
        FullViewingKey::from(&sk)
    }

    fn prepared_fixture() -> (FullViewingKey, FullViewingKey, Vec<u8>, Vec<[u8; 512]>) {
        let sender = fvk([7; 32]);
        let peer = fvk([8; 32]);
        let mut rho_bytes = [0; 32];
        rho_bytes[0] = 3;
        let rho = Option::<Rho>::from(Rho::from_bytes(&rho_bytes)).unwrap();
        let mut rseed_bytes = [0; 32];
        rseed_bytes[0] = 4;
        let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(rseed_bytes, &rho)).unwrap();
        let note = Option::<Note>::from(Note::from_parts(
            sender.address_at(0u32, Scope::External),
            NoteValue::from_raw(100_000_000),
            rho,
            rseed,
            NoteVersion::V2,
        ))
        .unwrap();
        let path =
            MerklePath::from_parts(0, core::array::from_fn(|i| <MerkleHashOrchard as Hashable>::empty_root(Level::from(i as u8))));
        let mut memos = Vec::new();
        let mut outputs = Vec::new();
        for i in 1..=4u32 {
            let mut memo = [0; 512];
            memo[0] = i as u8;
            memo[511] = (i + 20) as u8;
            memos.push(memo);
            outputs.push(PaymentOutputIntent {
                recipient: sender.address_at(i, Scope::External).to_raw_address_bytes(),
                amount: i as u64,
                memo,
            });
        }
        let mut peer_memo = [0; 512];
        peer_memo[..4].copy_from_slice(b"peer");
        memos.push(peer_memo);
        outputs.push(PaymentOutputIntent {
            recipient: peer.address_at(0u32, Scope::External).to_raw_address_bytes(),
            amount: 1,
            memo: peer_memo,
        });
        let mut internal_memo = [0; 512];
        internal_memo[..8].copy_from_slice(b"internal");
        internal_memo[511] = 42;
        memos.push(internal_memo);
        outputs.push(PaymentOutputIntent {
            recipient: sender.address_at(0u32, Scope::Internal).to_raw_address_bytes(),
            amount: 9,
            memo: internal_memo,
        });
        let prepared =
            prepare_payment_multi(&sender, vec![(note, path)], &outputs, 3_000_000, &[9; 32], b"ZKAS-shielded-payment-v1", true)
                .unwrap();
        (sender, peer, prepared.effects.to_bytes(), memos)
    }

    #[test]
    fn full_outputs_keep_self_indices_peer_and_exact_memos() {
        let (sender, peer, bytes, memos) = prepared_fixture();
        let sent = recover_full_outputs(&sender, &bytes).unwrap();
        let received = recover_full_outputs(&peer, &bytes).unwrap();
        assert_eq!(sent.len(), 7);
        assert_eq!(received.len(), 1);
        for i in 1..=4u32 {
            let row = sent.iter().find(|row| row.external_index == Some(i)).unwrap();
            assert_eq!(row.incoming_scopes, [ViewingScope::External]);
            assert_eq!(row.outgoing_scopes, [ViewingScope::External]);
            assert_eq!(row.value, i as u64);
            assert_eq!(row.memo, memos[(i - 1) as usize]);
        }
        let peer_address = peer.address_at(0u32, Scope::External).to_raw_address_bytes();
        let peer_row = sent.iter().find(|row| row.recipient == peer_address).unwrap();
        assert!(peer_row.incoming_scopes.is_empty());
        assert_eq!(peer_row.outgoing_scopes, [ViewingScope::External]);
        assert_eq!(peer_row.memo, memos[4]);
        assert_eq!(received[0].incoming_scopes, [ViewingScope::External]);
        assert!(received[0].outgoing_scopes.is_empty());
        assert_eq!(received[0].memo, memos[4]);
        let change = sent.iter().find(|row| row.external_index == Some(0)).unwrap();
        assert_eq!(change.incoming_scopes, [ViewingScope::External]);
        assert_eq!(change.outgoing_scopes, [ViewingScope::External]);
        assert_eq!(change.memo, [0; 512]);
        let internal_address = sender.address_at(0u32, Scope::Internal).to_raw_address_bytes();
        let internal = sent.iter().find(|row| row.recipient == internal_address).unwrap();
        assert_eq!(internal.external_index, None);
        assert_eq!(internal.incoming_scopes, [ViewingScope::Internal]);
        assert_eq!(internal.outgoing_scopes, [ViewingScope::External]);
        assert_eq!(internal.memo, memos[5]);
    }

    #[test]
    fn malformed_bundle_and_ciphertext_never_make_a_false_output() {
        let (sender, peer, bytes, _) = prepared_fixture();
        let mut trailing = bytes.clone();
        trailing.push(1);
        assert!(matches!(recover_full_outputs(&sender, &trailing), Err(FullMemoError::MalformedBundle)));
        assert!(matches!(recover_full_outputs(&sender, &vec![0; 500_001]), Err(FullMemoError::BundleTooLarge)));
        let mut bundle = crate::bundle::ShieldedBundle::from_bytes(&bytes).unwrap();
        bundle.actions[0].rk = [0; 32];
        assert!(matches!(recover_full_outputs(&sender, &bundle.to_bytes()), Err(FullMemoError::MalformedAction(0))));

        let peer_index = recover_full_outputs(&peer, &bytes).unwrap()[0].action_index;
        let mut damaged_recipient = crate::bundle::ShieldedBundle::from_bytes(&bytes).unwrap();
        damaged_recipient.actions[peer_index].enc_ciphertext[0] ^= 1;
        assert!(recover_full_outputs(&peer, &damaged_recipient.to_bytes()).unwrap().is_empty());

        let mut damaged_sender = crate::bundle::ShieldedBundle::from_bytes(&bytes).unwrap();
        damaged_sender.actions[peer_index].out_ciphertext[0] ^= 1;
        assert!(recover_full_outputs(&sender, &damaged_sender.to_bytes()).unwrap().iter().all(|row| row.action_index != peer_index));
        assert_eq!(recover_full_outputs(&peer, &damaged_sender.to_bytes()).unwrap().len(), 1);
        assert!(recover_full_outputs(&fvk([6; 32]), &bytes).unwrap().is_empty());
    }

    #[test]
    fn internal_ovk_is_recovered_without_internal_recipient_confusion() {
        use crate::wallet::build::{MultiOutput, MultiSpend, prepare_multiparty};
        let sender = fvk([7; 32]);
        let peer = fvk([8; 32]);
        let mut rho_bytes = [0; 32];
        rho_bytes[0] = 3;
        let rho = Option::<Rho>::from(Rho::from_bytes(&rho_bytes)).unwrap();
        let mut rseed_bytes = [0; 32];
        rseed_bytes[0] = 4;
        let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(rseed_bytes, &rho)).unwrap();
        let note = Option::<Note>::from(Note::from_parts(
            sender.address_at(0u32, Scope::External),
            NoteValue::from_raw(10_000_000),
            rho,
            rseed,
            NoteVersion::V2,
        ))
        .unwrap();
        let path =
            MerklePath::from_parts(0, core::array::from_fn(|i| <MerkleHashOrchard as Hashable>::empty_root(Level::from(i as u8))));
        let mut memo = [0; 512];
        memo[511] = 77;
        let prepared = prepare_multiparty(
            vec![MultiSpend { fvk: sender.clone(), note, path }],
            vec![MultiOutput {
                ovk: Some(sender.to_ovk(Scope::Internal)),
                recipient: peer.address_at(0u32, Scope::External).to_raw_address_bytes(),
                value: 9_000_000,
                memo,
            }],
            1_000_000,
            &[9; 32],
            b"ZKAS-shielded-payment-v1",
        )
        .unwrap();
        let bytes = prepared.payment.effects.to_bytes();
        let sent = recover_full_outputs(&sender, &bytes).unwrap();
        let received = recover_full_outputs(&peer, &bytes).unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(received.len(), 1);
        let peer_row = sent.iter().find(|row| row.recipient == peer.address_at(0u32, Scope::External).to_raw_address_bytes()).unwrap();
        assert!(peer_row.incoming_scopes.is_empty());
        assert_eq!(peer_row.outgoing_scopes, [ViewingScope::Internal]);
        assert_eq!(peer_row.memo, memo);
        assert_eq!(received[0].incoming_scopes, [ViewingScope::External]);
        assert!(received[0].outgoing_scopes.is_empty());
        assert_eq!(received[0].memo, memo);
    }
}
