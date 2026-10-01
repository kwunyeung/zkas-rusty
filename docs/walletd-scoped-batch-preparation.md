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

This API stops at unsigned preparation. It has no multi-output signing, finalization, journal, or broadcast route. The version-3 envelope still requires independent local approval and SDK signing checks; exact serialized transaction mass, proof/signature validation, acceptance, and retry-safe submission belong to finalization and submission. The legacy single-output API retains its existing behavior.
