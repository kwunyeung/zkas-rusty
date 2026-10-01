# Scoped multi-output preparation

This walletd profile prepares one non-custodial Orchard payment with several exact recipient outputs. It is available only when the daemon runs with custodial wallets and multiparty bundles disabled. A registered watch-only wallet supplies the viewing key internally; neither the browser capability nor the preparation request carries that key.

The wallet-controlled client calls `POST /api/wallet/prepare-many/capability` with its normal daemon bearer when configured, `X-Wallet-Token`, and a JSON body:

```json
{
  "origin": "https://wallet.example",
  "account": "zkas:...",
  "genesis": "64 lowercase hex characters",
  "logicalId": "64 lowercase hex characters",
  "outputs": [
    {"recipient": "zkas:...", "amountSompi": "1", "memoHex": "1024 lowercase hex characters"}
  ],
  "maxFeeSompi": "3000000"
}
```

The account must be the registered wallet's external address. The genesis must match the daemon's network. Each recipient must be a distinct shielded address other than the wallet's automatic change address; amounts are positive decimal sompi strings, and each memo is exactly 512 bytes. The body is limited to 64 KiB and unknown fields are rejected. Callers must encrypt any confidential application content before placing it in `memoHex`; walletd treats those bytes as opaque and does not parse an application message.

The response contains a random, short-lived `capability`, the `logicalId`, and `expiresAtUnix`. The logical ID is an idempotency key: replaying the same complete request within its lifetime returns the same capability and original expiry; a different intent for that wallet conflicts while the first is unresolved. A browser may call `POST /api/wallet/prepare-many` with `Authorization: Batch <capability>` and an exact matching `Origin` header. This route takes no body. It starts a detached proof once and returns `in_progress` or `prepared` status, with no prepared bundle or session material. A retry within the capability lifetime observes the same job even if the original HTTP connection closed. The wallet-controlled client calls `GET /api/wallet/prepare-many?logicalId=<id>` with its normal credentials to retrieve the version-3 prepared envelope and session after completion, including after the browser capability expires.

One reservation per normalized viewing key excludes concurrent legacy preparations and unexpired unsigned legacy sessions. The non-custodial profile also disables seed-backed background consolidation, including for seed wallets left on disk. Preparation uses matured wallet notes, a canonical checkpoint, one complete transaction, a fee at or below the approved ceiling, and recoverable positive outputs and change. Capacity is bounded to 64 active grants per daemon. Grants and unsigned prepared results are in memory; a restart drops them. Proving continues past the initial 15-minute capability lifetime, and a completed result receives a fresh 15-minute retrieval lifetime.

The wallet-controlled client independently checks the version-3 envelope against the locally approved intent and signs every real spend. It then calls `POST /api/wallet/finalize-many` using the normal wallet token and daemon bearer, with a JSON body:

```json
{
  "account": "zkas:...",
  "genesis": "64 lowercase hex characters",
  "logicalId": "64 lowercase hex characters",
  "session": "48 lowercase hex characters from the credentialed preparation response",
  "signatures": [{"actionIndex": 0, "signatureHex": "128 lowercase hex characters"}]
}
```

The body is limited to 16 KiB. The registered watch-only account, daemon genesis, logical ID, and session must all match the prepared request. Every requested real spend must have one unique valid signature; a missing, repeated, out-of-range, or invalid signature leaves the prepared session available for correction. A valid request finalizes once. The daemon checks the completed bundle proof, spend authorizations, binding signature, original recipient/amount/memo intent, fee ceiling, normal shielded-payment transaction context, actual serialized transaction mass, and conservative network mempool limits. The response contains `status: "finalized"`, `logicalId`, `transactionHex`, `txid`, and `sha256`. `transactionHex` is the complete Borsh-encoded signed `Transaction`, with the Orchard wire bundle in its payload; `sha256` hashes exactly those decoded transaction bytes. A retry with the same signatures within the finalized result's 15-minute lifetime returns the identical bytes and identifiers without finalizing again. Different signatures conflict. The finalized result remains reserved in memory; a restart loses it.

This increment does not submit or broadcast. Before a live send flow can use it, the next increment must durably write and fsync the signed bytes and intent association, recover an `UNKNOWN` outcome after uncertain submission or restart, reconcile transaction identity with the node before any retry, and gate legacy in-flight payments against the same viewing-key reservation. Until that journal and exact submit/status path exists, a finalized response is only an offline signed artifact. The legacy single-output API retains its existing behavior.
