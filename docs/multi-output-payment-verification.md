# Multi-output prepared-payment check

`shielded-core::payment_check::check_prepared_payment_multi` is a separate,
non-executable verification primitive. It does not change the existing
`check_prepared_payment` API or expose a prepare, sign, or submit route.

The caller supplies a nonempty list of `PaymentOutputIntent` values. Each binds
one canonical raw 43-byte Orchard recipient address, a positive sompi amount,
and the exact 512 memo bytes to be encrypted. Recipients must be distinct and
cannot equal the wallet's external index-zero change address. The
intent type omits `Debug` to avoid logging memo bytes. The
list and bundle must fit the existing `MAX_ACTIONS_PER_BUNDLE` consensus bound
(512). Approved amounts and their sum plus the fee must fit the signed `i64`
backend range. Fee and recipient selection remain caller policy.

For every action, the checker reconstructs the Orchard V2 note from disclosed
recipient, value, `rseed`, and the wire nullifier, then compares its note and
value commitments with the bundle. Each positive non-change output must match
one unused approved intent by address and amount. It independently derives the
Orchard V2 ephemeral key and full 580-byte recipient ciphertext from that note
and the approved memo, and compares both with the wire. Missing, extra,
repeated, split, merged, or memo-mutated payment outputs fail. Wallet-owned
positive change must also have the deterministic V2 ephemeral key and full
recipient ciphertext for its reconstructed note and an all-zero memo, so the
wallet can recover it. Zero-valued padding may remain without a ciphertext
check; it cannot move value. Disclosed spend and output totals must equal the
bundle's public value balance, which must equal the supplied actual fee and fit
the supplied fee ceiling.

This checker alone does not authorize any spend. A higher layer must bind the
approved account and network, verify input ownership and anchor, proof and
transaction mass, recompute the sighash locally, enforce signer/action indexes,
and handle preparation and submission. Outgoing-viewing-key ciphertext and
sender-history recovery are not checked by this primitive. Disclosed spend and
change values remain `u64`; their bounded totals use `i128`.

Run `cargo test -p kaspa-shielded-core payment_check::tests --lib --locked`
to exercise legacy behavior, distinct approved ciphertexts, memo and
ephemeral-key mutations, output multiplicity, recoverable change, padding,
commitments, fee accounting, disclosure coverage, and intent bounds.
