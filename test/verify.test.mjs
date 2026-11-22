import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateKeyPairSync, sign } from 'node:crypto';
import { canonicalJson, sha256HexSync as sha256Hex, verifyRecord, verifyRecords, buildPreimage, resolveVersion, TYPE_V2 } from '../src/verify.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const EXAMPLE_KEY = 'ab0aba4ac25570cf8c0b27a729fb47923461c9f9be7c3e60a982857685f8586c';
const load = (f) => JSON.parse(readFileSync(join(ROOT, 'examples', f), 'utf8'));
const codes = (r) => r.problems.map((p) => p.code);

// ---- the two published examples ----
test('original refusal passes with the example key', async () => {
  const r = await verifyRecord(load('refusal-original.json'), { publicKey: EXAMPLE_KEY });
  assert.equal(r.pass, true);
  assert.deepEqual(r.checks, { format: 'pass', content: 'pass', signature: 'pass', organisation: 'not_requested' });
  assert.equal(r.summary.decision, 'DENY');
  assert.deepEqual(r.summary.denyReasons, ['per_tx_cap_exceeded']);
  assert.equal(r.summary.amount, '9000000');
  assert.equal(r.summary.perTxCap, '5000000');
});

test('edited copy (DENY changed to APPROVE) fails on content', async () => {
  const r = await verifyRecord(load('refusal-edited.json'), { publicKey: EXAMPLE_KEY });
  assert.equal(r.pass, false);
  assert.deepEqual(codes(r), ['hash_mismatch']);
  assert.match(r.problems[0].detail, /recomputed f25a50c369889d9e/); // same value the repository's own verifier reported
});

test('the two examples differ only in decision and denyReasons', async () => {
  const a = load('refusal-original.json');
  const b = load('refusal-edited.json');
  const diff = Object.keys(a).filter((k) => JSON.stringify(a[k]) !== JSON.stringify(b[k]));
  assert.deepEqual(diff.sort(), ['decision', 'denyReasons']);
});

test('original fails under a different key', async () => {
  const { publicKey } = generateKeyPairSync('ed25519');
  const other = Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url').toString('hex');
  const r = await verifyRecord(load('refusal-original.json'), { publicKey: other });
  assert.deepEqual(codes(r), ['signature_invalid']);
});

test('changing any signed field fails', async () => {
  const base = load('refusal-original.json');
  for (const [k, v] of [['amount', '4000000'], ['payTo', `0x${'e9'.repeat(20)}`], ['agentId', 'agent_x'], ['createdAt', '2026-11-15T15:02:00.000Z'], ['policySnapshot', null], ['prevHash', 'GENESIS']]) {
    const r = await verifyRecord({ ...base, [k]: v }, { publicKey: EXAMPLE_KEY });
    assert.deepEqual(codes(r), ['hash_mismatch'], k);
  }
});

test('a changed signature fails', async () => {
  const base = load('refusal-original.json');
  const sig = base.signature.slice(0, -2) + (base.signature.endsWith('00') ? '01' : '00');
  assert.deepEqual(codes(await verifyRecord({ ...base, signature: sig }, { publicKey: EXAMPLE_KEY })), ['signature_invalid']);
});

test('an added field is rejected because the signature does not cover it', async () => {
  const r = await verifyRecord({ ...load('refusal-original.json'), approvedBy: 'finance' }, { publicKey: EXAMPLE_KEY });
  assert.equal(r.pass, false);
  assert.deepEqual(codes(r), ['unsigned_field']);
});

test('a partial or unknown version is rejected even though the signature is fine', async () => {
  const base = load('refusal-original.json');
  for (const v of [{ attestationType: TYPE_V2, schemaVersion: null }, { attestationType: null, schemaVersion: 2 }, { attestationType: TYPE_V2, schemaVersion: 3 }, { attestationType: 'com.counterroll.attestation.v2', schemaVersion: 2 }]) {
    assert.deepEqual(codes(await verifyRecord({ ...base, ...v }, { publicKey: EXAMPLE_KEY })), ['unrecognized_version']);
  }
});

test('--org style check', async () => {
  const base = load('refusal-original.json');
  assert.equal((await verifyRecord(base, { publicKey: EXAMPLE_KEY, expectedOrg: 'org_sample_verify' })).pass, true);
  assert.deepEqual(codes(await verifyRecord(base, { publicKey: EXAMPLE_KEY, expectedOrg: 'org_other' })), ['organisation_not_expected']);
});

test('a malformed key is refused', async () => {
  await assert.rejects(() => verifyRecord(load('refusal-original.json'), { publicKey: 'abc' }), TypeError);
});

// ---- records made here with a throwaway key, both forms ----
function keypair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return { privateKey, hex: Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url').toString('hex') };
}
function makeRecord(k, fields, typed) {
  const r = {
    id: `att_${fields.seq}`, organizationId: 'org_test', seq: fields.seq, agentId: 'agent_t', policyId: 'policy_t',
    decision: 'APPROVE', denyReasons: [], network: 'eip155:84532', asset: '0x01', payTo: '0x02', amount: '1000000',
    eip3009Nonce: 'aa', payloadSha256: 'bb', requirements: { scheme: 'exact' }, policySnapshot: { perTxCap: '5000000' },
    prevHash: fields.prevHash, createdAt: '2026-11-22T00:00:00.000Z',
    attestationType: typed ? TYPE_V2 : null, schemaVersion: typed ? 2 : null,
  };
  const resolved = resolveVersion(r);
  r.hash = sha256Hex(canonicalJson(buildPreimage(r, resolved)));
  r.signature = sign(null, Buffer.from(r.hash, 'hex'), k.privateKey).toString('hex');
  return r;
}
function chain(k, n, typed) {
  const out = [];
  for (let i = 1; i <= n; i++) out.push(makeRecord(k, { seq: String(i), prevHash: i === 1 ? 'GENESIS' : out[i - 2].hash }, typed));
  return out;
}

test('typed (schema 2) records verify, and removing the type breaks the hash', async () => {
  const k = keypair();
  const r = makeRecord(k, { seq: '1', prevHash: 'GENESIS' }, true);
  assert.equal((await verifyRecord(r, { publicKey: k.hex })).pass, true);
  assert.deepEqual(codes(await verifyRecord({ ...r, attestationType: null, schemaVersion: null }, { publicKey: k.hex })), ['hash_mismatch']);
});

test('absent version fields mean the untyped form', async () => {
  const k = keypair();
  const r = makeRecord(k, { seq: '1', prevHash: 'GENESIS' }, false);
  delete r.attestationType;
  delete r.schemaVersion;
  assert.equal((await verifyRecord(r, { publicKey: k.hex })).pass, true);
});

test('a list passes as a chain from seq 1', async () => {
  const k = keypair();
  const c = chain(k, 4, false);
  const r = await verifyRecords(c, { publicKey: k.hex });
  assert.equal(r.pass, true);
  assert.equal(r.continuity, 'pass');
  assert.equal(r.completeness, 'not_verified');
});

test('removing, reordering or dropping the first record of a list fails', async () => {
  const k = keypair();
  const c = chain(k, 4, true);
  assert.equal((await verifyRecords([c[0], c[2], c[3]], { publicKey: k.hex })).pass, false);
  assert.equal((await verifyRecords([c[1], c[0], c[2], c[3]], { publicKey: k.hex })).pass, false);
  assert.equal((await verifyRecords(c.slice(1), { publicKey: k.hex })).pass, false);
});

test('dropping the last record passes without a trusted head and fails with one', async () => {
  const k = keypair();
  const c = chain(k, 4, false);
  const head = { seq: '4', hash: c[3].hash };
  assert.equal((await verifyRecords(c.slice(0, 3), { publicKey: k.hex })).pass, true); // the stated limit
  const r = await verifyRecords(c.slice(0, 3), { publicKey: k.hex, head });
  assert.equal(r.pass, false);
  assert.equal(r.head, 'fail');
  assert.equal((await verifyRecords(c, { publicKey: k.hex, head })).head, 'pass');
});

test('a chain re-signed with another key fails under the trusted key', async () => {
  const genuine = keypair();
  const forger = keypair();
  const forged = chain(forger, 3, false);
  assert.equal((await verifyRecords(forged, { publicKey: forger.hex })).pass, true); // why the key must come from elsewhere
  assert.equal((await verifyRecords(forged, { publicKey: genuine.hex })).pass, false);
});

// ---- canonical JSON vectors (FORMAT.md §4.1) ----
test('canonical JSON vectors', async () => {
  const hex = (v) => Buffer.from(canonicalJson(v), 'utf8').toString('hex');
  assert.equal(hex({ b: 1, a: 2, c: 3 }), '7b2261223a322c2262223a312c2263223a337d');
  assert.equal(hex({ '\u{10000}': 'supp', '￿': 'bmp' }), '7b22f0908080223a2273757070222c22efbfbf223a22626d70227d');
  assert.equal(hex({ s: 'a"b\\c\nd\u0001f' }), '7b2273223a22615c22625c5c635c6e645c753030303166227d');
  assert.equal(hex({ s: 'é' }), '7b2273223a22c3a9227d');
  assert.equal(hex({ s: 'é' }), '7b2273223a2265cc81227d');
  assert.equal(hex({ n: -0 }), '7b226e223a307d');
  assert.throws(() => canonicalJson({ a: undefined }), TypeError);
  assert.throws(() => canonicalJson({ a: 10n }), TypeError);
  assert.throws(() => canonicalJson({ a: 1.5 }), TypeError);
  assert.throws(() => canonicalJson({ a: Number.MAX_SAFE_INTEGER + 1 }), TypeError);
  assert.equal(hex({ arr: [1, null, true, false, 'x'] }), '7b22617272223a5b312c6e756c6c2c747275652c66616c73652c2278225d7d');
  assert.equal(hex({ z: [{ y: 1, x: 2 }], a: 'end' }), '7b2261223a22656e64222c227a223a5b7b2278223a322c2279223a317d5d7d');
});

// ---- command line ----
const cli = (...args) => spawnSync(process.execPath, [join(ROOT, 'bin', 'counterroll-verify.mjs'), ...args], { encoding: 'utf8' });

test('CLI: original exits 0, edited exits 1', async () => {
  const a = cli(join(ROOT, 'examples', 'refusal-original.json'), '--key', EXAMPLE_KEY);
  assert.equal(a.status, 0, a.stderr);
  assert.match(a.stdout, /RESULT: PASS/);
  assert.match(a.stdout, /never shows: that the decision was correct, that any money moved/);
  const b = cli(join(ROOT, 'examples', 'refusal-edited.json'), '--key', EXAMPLE_KEY);
  assert.equal(b.status, 1);
  assert.match(b.stdout, /RESULT: FAIL/);
  assert.match(b.stdout, /hash_mismatch/);
});

test('CLI: refuses to run without --key, exits 2', async () => {
  const r = cli(join(ROOT, 'examples', 'refusal-original.json'));
  assert.equal(r.status, 2);
  assert.match(r.stderr, /--key is required/);
});

test('CLI: --json output', async () => {
  const r = cli(join(ROOT, 'examples', 'refusal-original.json'), '--key', EXAMPLE_KEY, '--json');
  assert.equal(r.status, 0);
  const j = JSON.parse(r.stdout);
  assert.equal(j.pass, true);
  assert.equal(j.completeness, 'not_verified');
});
