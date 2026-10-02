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

The approved application origin may use HTTPS under the existing origin policy. For local development, HTTP is accepted only as `http://localhost:<port>` or `http://127.0.0.1:<port>`, with an explicit canonical port from 1 to 65535 other than 80. No hostname aliases, remote HTTP origins, paths, query strings, fragments, credentials, or omitted ports are accepted. The configured CORS allow-list must still contain the exact browser Origin; permitting a loopback origin in the grant does not bypass CORS or the capability's exact-Origin binding.

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

The body is limited to 16 KiB. The registered watch-only account, daemon genesis, logical ID, and session must all match the prepared request. Every requested real spend must have one unique valid signature; a missing, repeated, out-of-range, or invalid signature leaves the prepared session available for correction. A valid request finalizes once. The daemon checks the completed bundle proof, spend authorizations, binding signature, original recipient/amount/memo intent, fee ceiling, normal shielded-payment transaction context, actual serialized transaction mass, and conservative network mempool limits. The response contains `status: "finalized"`, `logicalId`, `transactionHex`, `txid`, and `sha256`. `transactionHex` is the complete Borsh-encoded signed `Transaction`, with the Orchard wire bundle in its payload; `sha256` hashes exactly those decoded transaction bytes. A retry with the same signatures within the finalized result's 15-minute lifetime returns the identical bytes and identifiers without finalizing again. Different signatures conflict. The finalized result remains reserved across restart by its private journal.

The daemon fsyncs the exact signed bytes and their wallet, network, intent, and logical-ID binding before returning them. After restart, the credentialed wallet can retrieve the same bytes with `GET /api/wallet/finalize-many/journal?account=<address>&genesis=<hex>&logicalId=<hex>`. The short-lived unsigned session is not needed for this recovery.

The wallet-controlled client calls `POST /api/wallet/submit-many` with its normal credentials and `account`, `genesis`, `logicalId`, `txid`, and `sha256`. The daemon loads the signed bytes from its private journal, checks the exact identifiers, and fsyncs `unknown` before calling the configured node. It submits only the journaled bytes. Repeating the request can resubmit only those same bytes; an absent mempool entry, RPC timeout, restart, or lost HTTP response never authorizes a newly proved payment. The credentialed `GET /api/wallet/submit-many/status?account=<address>&genesis=<hex>&logicalId=<hex>` reports `finalized_unsent`, `unknown`, `mempool`, `included`, `settled`, or `conflicted` with the transaction identity and, when known, inclusion block and DAA. These statuses are observations from the configured self-run node and wallet scanner, not independent finality proofs. Missing selected-chain history or an unusable replay cursor retains the reservation.

The daemon releases a wallet's journal reservation only after it rechecks selected-chain acceptance, the node is synced, at least 600 DAA have passed since inclusion, and the caught-up wallet scan has consumed the spent positions through that depth. A fresh reconciliation precedes a new preparation. Acceptance lookup walks bounded selected-chain pages from the node's retained checkpoint. A timeout, missing page, or exhausted walk budget preserves the last inclusion and replay cursor as unresolved, including when many blocks share one DAA. Absence is not evidence of rejection. The legacy single-output watch-only prepare route retains its request shape but now requires a matching registered watch-only wallet token, so uncertain submissions remain discoverable. Its submit route shares the journal and viewing-key exclusion. If its response is lost, that token can call `GET /api/wallet/submit/uncertain` to discover up to 32 unresolved legacy transaction identities, then inspect their status. A legacy node error after a send attempt reports an unknown outcome rather than claiming no coins moved.

The private journal lives under the configured wallet directory, with an exclusive daemon lock and an fsynced inventory file beside the journal directory. Missing or corrupted inventory stops startup. A newly created wallet directory receives a network-bound enablement marker automatically. An existing wallet directory requires an operator to quiesce old payment clients, reconcile every preexisting in-flight or uncertain legacy spend against the synced selected chain and wallet state, and then write the exact UTF-8 line `zkas-walletd-batch-journal-v1:<lowercase genesis hex>` plus a newline to `batch-journal-enabled` in that wallet directory with private file permissions and durable filesystem sync, then restart the daemon. Until the marker is validated at startup, new watch-only preparations and automatic pending-spend reclamation are disabled. An empty new journal does not establish that older submissions were resolved.
