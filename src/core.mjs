// Counterroll record verifier: shared engine (Node.js and browser).
//
// Checks a Counterroll decision record (format: FORMAT.md) against a public
// key the caller supplies. No network, no file access, no clock. The key is
// never taken from the record. The two crypto primitives are passed in, so
// the same checks run in Node.js (src/verify.mjs) and in a browser
// (web/app.mjs):
//   sha256Hex(text: string) -> Promise<string>   lowercase hex of SHA-256(UTF-8(text))
//   ed25519Verify(publicKeyHex, messageBytes: Uint8Array, signatureHex) -> Promise<boolean>

export const VERIFIER_VERSION = '0.1.0';
export const GENESIS = 'GENESIS';
export const TYPE_V2 = 'com.counterroll.attestation';

// The 17 signed fields every decision record carries (FORMAT.md §3).
export const SIGNED_FIELDS = [
  'id', 'organizationId', 'seq', 'agentId', 'policyId', 'decision', 'denyReasons',
  'network', 'asset', 'payTo', 'amount', 'eip3009Nonce', 'payloadSha256',
  'requirements', 'policySnapshot', 'prevHash', 'createdAt',
];
// Fields a record may also carry. Anything else is rejected: an extra field
// is not covered by the signature, so it could say anything.
const VERSION_FIELDS = ['attestationType', 'schemaVersion'];
const ENVELOPE_FIELDS = ['hash', 'signature'];
const ALLOWED_FIELDS = new Set([...SIGNED_FIELDS, ...VERSION_FIELDS, ...ENVELOPE_FIELDS]);

const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;
const DIGITS = /^(0|[1-9][0-9]*)$/;
const ISO_MS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

// ---- canonical JSON (FORMAT.md §4) ----
export function canonicalJson(value) {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'string':
      return JSON.stringify(value);
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isSafeInteger(value)) {
        throw new TypeError(`canonicalJson: only safe integers are serializable, got ${value}`);
      }
      return String(value);
    case 'bigint':
      throw new TypeError('canonicalJson: convert BigInt to a string before serializing');
    case 'undefined':
      throw new TypeError('canonicalJson: undefined is not serializable');
    default:
      break;
  }
  if (Array.isArray(value)) return `[${value.map((v) => canonicalJson(v)).join(',')}]`;
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort();
    const parts = [];
    for (const key of keys) {
      const v = value[key];
      if (v === undefined) throw new TypeError(`canonicalJson: key "${key}" is undefined`);
      parts.push(`${JSON.stringify(key)}:${canonicalJson(v)}`);
    }
    return `{${parts.join(',')}}`;
  }
  throw new TypeError(`canonicalJson: cannot serialize a ${typeof value}`);
}

export function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// ---- key handling ----
export function normalizeKey(input) {
  const hex = String(input ?? '').trim().toLowerCase().replace(/^0x/, '');
  if (!HEX64.test(hex)) return null;
  return hex;
}

// ---- version resolution (FORMAT.md §5): closed set, no fallthrough ----
export function resolveVersion(record) {
  const type = record.attestationType ?? null;
  const schemaVersion = record.schemaVersion ?? null;
  if (type === null && schemaVersion === null) return { ok: true, version: 1, label: 'untyped form' };
  if (type === TYPE_V2 && schemaVersion === 2) return { ok: true, version: 2, label: `typed form (${TYPE_V2}, schema 2)` };
  return {
    ok: false,
    detail: `unrecognized record type/version (attestationType=${JSON.stringify(type)}, schemaVersion=${JSON.stringify(schemaVersion)})`,
  };
}

export function buildPreimage(record, resolved) {
  const base = {};
  for (const f of SIGNED_FIELDS) base[f] = record[f];
  if (resolved.version === 2) {
    base.type = TYPE_V2;
    base.schemaVersion = 2;
  }
  return base;
}

// ---- shape (FORMAT.md §3) ----
function shapeProblems(r) {
  const p = [];
  const add = (detail) => p.push({ code: 'bad_shape', detail });
  if (r === null || typeof r !== 'object' || Array.isArray(r)) {
    add('a record must be a JSON object');
    return p;
  }
  for (const k of Object.keys(r)) {
    if (!ALLOWED_FIELDS.has(k)) p.push({ code: 'unsigned_field', detail: `field "${k}" is not part of the format and is not covered by the signature` });
  }
  for (const f of SIGNED_FIELDS) if (!(f in r)) add(`missing signed field "${f}"`);
  if (p.length) return p;
  const str = (f) => typeof r[f] === 'string' || add(`"${f}" must be a string`);
  ['id', 'organizationId', 'agentId', 'network', 'asset', 'payTo', 'eip3009Nonce', 'payloadSha256', 'prevHash'].forEach(str);
  if (typeof r.seq !== 'string' || !DIGITS.test(r.seq) || r.seq === '0') add('"seq" must be a decimal string of 1 or more');
  if (typeof r.amount !== 'string' || !DIGITS.test(r.amount)) add('"amount" must be a decimal string in atomic units');
  if (r.decision !== 'APPROVE' && r.decision !== 'DENY') add('"decision" must be "APPROVE" or "DENY"');
  if (!Array.isArray(r.denyReasons) || !r.denyReasons.every((x) => typeof x === 'string')) add('"denyReasons" must be an array of strings');
  if (r.policyId !== null && typeof r.policyId !== 'string') add('"policyId" must be a string or null');
  if (typeof r.createdAt !== 'string' || !ISO_MS.test(r.createdAt)) add('"createdAt" must be an ISO-8601 UTC time with milliseconds');
  if (typeof r.requirements !== 'object' || r.requirements === null || Array.isArray(r.requirements)) add('"requirements" must be an object');
  if (r.policySnapshot !== null && (typeof r.policySnapshot !== 'object' || Array.isArray(r.policySnapshot))) add('"policySnapshot" must be an object or null');
  if (typeof r.prevHash === 'string' && r.prevHash !== GENESIS && !HEX64.test(r.prevHash)) add('"prevHash" must be "GENESIS" or 64 lowercase hex characters');
  if (typeof r.hash !== 'string' || !HEX64.test(r.hash)) add('"hash" must be 64 lowercase hex characters');
  if (typeof r.signature !== 'string' || !HEX128.test(r.signature)) add('"signature" must be 128 lowercase hex characters');
  return p;
}

/**
 * Verify one record. Returns { pass, checks, problems, summary }.
 * checks.* are "pass" | "fail" | "not_checked".
 */
export async function verifyRecord(record, { publicKey, expectedOrg, crypto } = {}) {
  if (!crypto || typeof crypto.sha256Hex !== 'function' || typeof crypto.ed25519Verify !== 'function') throw new TypeError('crypto primitives are required');
  const key = normalizeKey(publicKey);
  if (!key) throw new TypeError('publicKey must be a 32-byte Ed25519 public key in hex (64 characters)');
  const checks = { format: 'not_checked', content: 'not_checked', signature: 'not_checked', organisation: expectedOrg ? 'not_checked' : 'not_requested' };
  const problems = shapeProblems(record);
  const summary = summarize(record);
  if (problems.length) {
    checks.format = 'fail';
    return { pass: false, checks, problems, summary };
  }
  const resolved = resolveVersion(record);
  if (!resolved.ok) {
    checks.format = 'fail';
    problems.push({ code: 'unrecognized_version', detail: resolved.detail });
    return { pass: false, checks, problems, summary };
  }
  checks.format = 'pass';
  summary.form = resolved.label;

  let recomputed;
  try {
    recomputed = await crypto.sha256Hex(canonicalJson(buildPreimage(record, resolved)));
  } catch (e) {
    problems.push({ code: 'not_canonicalizable', detail: e.message });
  }
  if (recomputed !== undefined) {
    if (recomputed === record.hash) checks.content = 'pass';
    else {
      checks.content = 'fail';
      problems.push({ code: 'hash_mismatch', detail: `stored hash ${record.hash}, recomputed ${recomputed}: the record was changed after it was signed` });
    }
  } else checks.content = 'fail';

  if (await crypto.ed25519Verify(key, hexToBytes(record.hash), record.signature)) checks.signature = 'pass';
  else {
    checks.signature = 'fail';
    problems.push({ code: 'signature_invalid', detail: 'the signature does not verify with the key you supplied' });
  }

  if (expectedOrg) {
    if (record.organizationId === expectedOrg) checks.organisation = 'pass';
    else {
      checks.organisation = 'fail';
      problems.push({ code: 'organisation_not_expected', detail: `record belongs to ${JSON.stringify(record.organizationId)}, not ${JSON.stringify(expectedOrg)}` });
    }
  }
  const pass = checks.format === 'pass' && checks.content === 'pass' && checks.signature === 'pass' && checks.organisation !== 'fail';
  return { pass, checks, problems, summary };
}

function summarize(r) {
  if (r === null || typeof r !== 'object' || Array.isArray(r)) return {};
  const pick = (k) => (typeof r[k] === 'string' ? r[k] : undefined);
  const snap = r.policySnapshot && typeof r.policySnapshot === 'object' ? r.policySnapshot : null;
  return {
    id: pick('id'), organizationId: pick('organizationId'), seq: pick('seq'), agentId: pick('agentId'),
    decision: pick('decision'), denyReasons: Array.isArray(r.denyReasons) ? r.denyReasons : undefined,
    amount: pick('amount'), payTo: pick('payTo'), network: pick('network'), asset: pick('asset'),
    policyId: r.policyId ?? null, perTxCap: snap && typeof snap.perTxCap === 'string' ? snap.perTxCap : undefined,
    createdAt: pick('createdAt'),
  };
}

/**
 * Verify a list of records presented in ascending order. Each record is
 * verified on its own, then the links between them are checked
 * ("presented-chain continuity"). Optionally compares the last record with a
 * head { seq, hash } the caller already trusted.
 */
export async function verifyRecords(records, { publicKey, expectedOrg, head, crypto } = {}) {
  if (!Array.isArray(records) || records.length === 0) throw new TypeError('records must be a non-empty array');
  const results = [];
  for (const r of records) results.push(await verifyRecord(r, { publicKey, expectedOrg, crypto }));
  const links = [];
  // A list is checked as an organisation's chain from its first record, the
  // way FORMAT.md §6 re-derives it: seq 1, prevHash "GENESIS", then each
  // record naming the hash of the one before it.
  let continuity = 'pass';
  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    if (results[i].checks.format !== 'pass') { continuity = 'fail'; continue; }
    if (i === 0) {
      if (r.seq !== '1') {
        links.push({ code: 'sequence_gap', detail: `a list must start at seq 1; this one starts at seq ${r.seq}` });
        continuity = 'fail';
      }
      if (r.prevHash !== GENESIS) {
        links.push({ code: 'broken_link', detail: 'the first record must have prevHash "GENESIS"' });
        continuity = 'fail';
      }
      continue;
    }
    const prev = records[i - 1];
    if (results[i - 1].checks.format !== 'pass') continue;
    if (r.organizationId !== prev.organizationId) { links.push({ code: 'org_mismatch', detail: `record ${i + 1} belongs to a different organisation` }); continuity = 'fail'; }
    if (BigInt(r.seq) !== BigInt(prev.seq) + 1n) { links.push({ code: 'sequence_gap', detail: `seq ${prev.seq} is followed by seq ${r.seq}` }); continuity = 'fail'; }
    if (r.prevHash !== prev.hash) { links.push({ code: 'broken_link', detail: `seq ${r.seq} does not name the hash of seq ${prev.seq}` }); continuity = 'fail'; }
  }
  let headCheck = 'not_supplied';
  if (head) {
    const last = records[records.length - 1];
    if (String(head.seq) === last.seq && String(head.hash).toLowerCase() === last.hash) headCheck = 'pass';
    else {
      headCheck = 'fail';
      links.push({ code: 'head_mismatch', detail: `your trusted head is seq ${head.seq} ${String(head.hash).slice(0, 12)}…; the last record presented is seq ${last.seq} ${String(last.hash).slice(0, 12)}…` });
    }
  }
  const pass = results.every((x) => x.pass) && continuity !== 'fail' && headCheck !== 'fail';
  return { pass, results, continuity, head: headCheck, linkProblems: links, completeness: 'not_verified' };
}
