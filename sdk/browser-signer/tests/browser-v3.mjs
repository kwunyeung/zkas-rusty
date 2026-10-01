import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
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
