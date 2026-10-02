import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const output = resolve(process.argv[2] ?? "");
if (!process.argv[2]) throw new Error("pass the wasm-pack output directory");
const { initSync, PrivateAccountSigner } = await import(pathToFileURL(join(output, "zkas_browser_signer.js")));
initSync({ module: readFileSync(join(output, "zkas_browser_signer_bg.wasm")) });
const fixture = JSON.parse(readFileSync(new URL("./fixtures/v3-payment.json", import.meta.url)));
const prepared = JSON.stringify(fixture.preparedEnvelope);

function create(intent = fixture.approvedIntent, genesis = fixture.genesisHex, network = "mainnet") {
    const seed = Uint8Array.from(Buffer.from(fixture.accountSeedHex, "hex"));
    const signer = new PrivateAccountSigner(seed, network, genesis, JSON.stringify(intent));
    assert.ok(seed.every(byte => byte === 0), "the caller's seed buffer must be cleared");
    return signer;
}

const signer = create();
assert.equal(signer.approved_account(), fixture.approvedIntent.account);
const signatures = JSON.parse(signer.sign_prepared_v3(prepared));
assert.equal(signatures.length, 1);
assert.equal(signatures[0].actionIndex, 0);
assert.match(signatures[0].signatureHex, /^[0-9a-f]{128}$/);
if (process.argv[3]) writeFileSync(process.argv[3], JSON.stringify(signatures));
for (const [name, envelope] of Object.entries(fixture.rejectedEnvelopes)) {
    assert.throws(() => signer.sign_prepared_v3(JSON.stringify(envelope)), undefined, name);
}
assert.throws(() => signer.sign_prepared_v3("{"));
assert.throws(() => signer.sign_prepared_v3("x".repeat(512 * 1024 + 1)));
const corrupt = structuredClone(fixture.preparedEnvelope);
corrupt.outputs[0].memo = "00".repeat(512);
assert.throws(() => signer.sign_prepared_v3(JSON.stringify(corrupt)));
signer.free();

const wrongGenesis = create(fixture.approvedIntent, "56".repeat(32));
assert.throws(() => wrongGenesis.sign_prepared_v3(prepared));
wrongGenesis.free();
const wrongFee = structuredClone(fixture.approvedIntent);
wrongFee.maxFeeSompi = "2999999";
const feeSigner = create(wrongFee);
assert.throws(() => feeSigner.sign_prepared_v3(prepared));
feeSigner.free();
const wrongMemo = structuredClone(fixture.approvedIntent);
wrongMemo.outputs[0].memoHex = "00".repeat(512);
const memoSigner = create(wrongMemo);
assert.throws(() => memoSigner.sign_prepared_v3(prepared));
memoSigner.free();

for (const [network, intent] of [
    ["testnet", fixture.approvedIntent],
    ["mainnet", { ...fixture.approvedIntent, account: fixture.approvedIntent.outputs[0].recipient }],
    ["mainnet", { ...fixture.approvedIntent, outputs: Array(9).fill(fixture.approvedIntent.outputs[0]) }],
]) {
    const seed = Uint8Array.from(Buffer.from(fixture.accountSeedHex, "hex"));
    assert.throws(() => new PrivateAccountSigner(seed, network, fixture.genesisHex, JSON.stringify(intent)));
    assert.ok(seed.every(byte => byte === 0), "failed construction must also clear the seed buffer");
}

console.log("browser signer WASM: verified signatures, seed clearing, and negative parity cases");


const finalizedFixture = JSON.parse(readFileSync(new URL("./fixtures/v3-finalized.json", import.meta.url)));
const finalSeed = Uint8Array.from(Buffer.from(finalizedFixture.provenance.accountSeedHex, "hex"));
const finalSigner = new PrivateAccountSigner(finalSeed, "mainnet", finalizedFixture.genesisHex, JSON.stringify(finalizedFixture.approvedIntent));
assert.ok(finalSeed.every(byte => byte === 0));
assert.throws(() => finalSigner.verify_finalized_v3(finalizedFixture.transactionHex));
const finalPrepared = JSON.stringify(finalizedFixture.preparedEnvelope);
const finalSignatures = finalSigner.sign_prepared_v3(finalPrepared);
assert.equal(finalSigner.sign_prepared_v3(finalPrepared), finalSignatures);
assert.throws(() => finalSigner.sign_prepared_v3(prepared));
const repo = resolve(fileURLToPath(new URL("../../..", import.meta.url)));
function finalized(signatures, mode = "valid") {
    return execFileSync("cargo", ["run", "--offline", "--locked", "--quiet", "-p", "zkas-browser-signer", "--example", "finalize_v3_fixture", "--", signatures, mode], { cwd: repo, encoding: "utf8" }).trim();
}
const exact = finalized(finalSignatures);
const verified = JSON.parse(finalSigner.verify_finalized_v3(exact));
assert.equal(verified.transactionHex, exact);
assert.match(verified.txid, /^[0-9a-f]{64}$/);
assert.match(verified.sha256, /^[0-9a-f]{64}$/);
assert.deepEqual(JSON.parse(finalSigner.verify_finalized_v3(exact)), verified);
assert.throws(() => finalSigner.verify_finalized_v3(finalizedFixture.transactionHex), /a different finalized transaction was already verified/);
const errors = {
    proof: /completed payment proof invalid/,
    spend: /completed payment spend authorization invalid/,
    binding: /completed payment binding signature invalid/,
    effect: /finalized effects differ from signed payment/,
    version: /noncanonical payment transaction/,
    mass: /noncanonical payment transaction length or mass/,
    "cached-id": /cached transaction ID differs from computed ID/,
    trailing: /noncanonical payment transaction length or mass/,
    "payload-length": /noncanonical payment transaction length or mass/,
};
for (const [mode, expected] of Object.entries(errors)) {
    const seed = Uint8Array.from(Buffer.from(finalizedFixture.provenance.accountSeedHex, "hex"));
    const fresh = new PrivateAccountSigner(seed, "mainnet", finalizedFixture.genesisHex, JSON.stringify(finalizedFixture.approvedIntent));
    const signatures = fresh.sign_prepared_v3(finalPrepared);
    assert.throws(() => fresh.verify_finalized_v3(finalized(signatures, mode)), expected, mode);
    fresh.free();
}
assert.throws(() => finalSigner.verify_finalized_v3("00"));
finalSigner.free();
console.log("browser finalized WASM: full proof, spend, binding, transaction shape and exact-handle checks passed");
