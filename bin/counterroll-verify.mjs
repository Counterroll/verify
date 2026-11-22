#!/usr/bin/env node
// Counterroll record verifier: command line.
// Offline. Reads only the file you name. Never takes the key from that file.

import { readFileSync } from 'node:fs';
import { VERIFIER_VERSION, normalizeKey, verifyRecord, verifyRecords } from '../src/verify.mjs';

const USAGE = `Counterroll record verifier ${VERIFIER_VERSION}

Usage:
  counterroll-verify <record.json> --key <public-key-hex> [options]

  <record.json>   One decision record (a JSON object), or an organisation's
                  records as a JSON array in order, starting at seq 1.

Options:
  --key <hex>     The Ed25519 public key you trust for this organisation
                  (64 hex characters). Required. Get it by a route you trust,
                  never from the file you are checking. See README.md.
  --org <id>      Fail unless every record belongs to this organisation.
  --head <seq>:<hash>
                  A last record you already trusted. Fails if the last record
                  presented is a different one. Only with a list.
  --json          Machine-readable output.
  -h, --help      Show this help.

Exit codes: 0 pass, 1 fail, 2 could not run (bad arguments or unreadable file).
`;

function parseArgs(argv) {
  const o = { json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const need = () => {
      if (i + 1 >= argv.length) throw new Error(`${a} needs a value`);
      return argv[++i];
    };
    if (a === '-h' || a === '--help') o.help = true;
    else if (a === '--key') o.key = need();
    else if (a === '--org') o.org = need();
    else if (a === '--head') o.head = need();
    else if (a === '--json') o.json = true;
    else if (a.startsWith('-')) throw new Error(`unknown option ${a}`);
    else if (o.file === undefined) o.file = a;
    else throw new Error(`unexpected argument ${a}`);
  }
  return o;
}

function die(message) {
  process.stderr.write(`counterroll-verify: ${message}\n\n${USAGE}`);
  process.exit(2);
}

let opts;
try {
  opts = parseArgs(process.argv.slice(2));
} catch (e) {
  die(e.message);
}
if (opts.help) {
  process.stdout.write(USAGE);
  process.exit(0);
}
if (!opts.file) die('name a record file');
if (!opts.key) die('--key is required: the verifier never reads the key from the file being checked');
const key = normalizeKey(opts.key);
if (!key) die('--key must be 64 hex characters (a 32-byte Ed25519 public key)');

let head;
if (opts.head) {
  const m = /^(\d+):([0-9a-fA-F]{64})$/.exec(opts.head);
  if (!m) die('--head must look like <seq>:<64 hex characters>');
  head = { seq: m[1], hash: m[2].toLowerCase() };
}

let input;
try {
  input = JSON.parse(readFileSync(opts.file, 'utf8'));
} catch (e) {
  die(`could not read ${opts.file} as JSON: ${e.message}`);
}

const isList = Array.isArray(input);
if (isList && input.length === 0) die('the list is empty');
if (head && !isList) die('--head applies only to a list of records');

const report = isList
  ? await verifyRecords(input, { publicKey: key, expectedOrg: opts.org, head })
  : await (async () => {
      const r = await verifyRecord(input, { publicKey: key, expectedOrg: opts.org });
      return { pass: r.pass, results: [r], continuity: 'not_checked', head: 'not_supplied', linkProblems: [], completeness: 'not_verified' };
    })();

if (opts.json) {
  process.stdout.write(`${JSON.stringify({ verifier: `counterroll-verify ${VERIFIER_VERSION}`, file: opts.file, trustedKey: key, ...report }, null, 2)}\n`);
  process.exit(report.pass ? 0 : 1);
}

const short = (h) => (typeof h === 'string' && h.length > 16 ? `${h.slice(0, 8)}…${h.slice(-4)}` : String(h));
const word = { pass: 'PASS', fail: 'FAIL', not_checked: 'not checked', not_requested: 'not requested', not_supplied: 'not supplied' };
const lines = [];
lines.push(`Counterroll record verifier ${VERIFIER_VERSION} (offline)`);
lines.push(`File:         ${opts.file}`);
lines.push(`Trusted key:  ${short(key)}  (supplied by you with --key)`);
lines.push('');

report.results.forEach((r, i) => {
  const s = r.summary;
  const label = isList ? `Record ${i + 1}` : 'Record';
  lines.push(`${label}: seq ${s.seq ?? '?'} · ${s.id ?? '(no id)'} · organisation ${s.organizationId ?? '?'}`);
  if (s.decision) {
    const reasons = s.denyReasons && s.denyReasons.length ? ` (${s.denyReasons.join(', ')})` : '';
    lines.push(`  Says:       ${s.decision}${reasons} · agent ${s.agentId ?? '?'} · amount ${s.amount ?? '?'} atomic units to ${s.payTo ?? '?'}`);
    if (s.policyId) lines.push(`              policy ${s.policyId}${s.perTxCap ? `, per-payment cap ${s.perTxCap}` : ''} · recorded ${s.createdAt ?? '?'}`);
  }
  lines.push(`  Format:     ${word[r.checks.format]}${s.form ? ` (${s.form})` : ''}`);
  lines.push(`  Content:    ${r.checks.content === 'pass' ? 'PASS (matches the signed hash)' : r.checks.content === 'fail' ? 'FAIL (does not match the signed hash: changed after signing)' : word[r.checks.content]}`);
  lines.push(`  Signature:  ${r.checks.signature === 'pass' ? 'PASS (the stored hash was signed by the trusted key)' : word[r.checks.signature]}`);
  if (r.checks.organisation !== 'not_requested') lines.push(`  Org:        ${word[r.checks.organisation]}`);
  for (const p of r.problems) lines.push(`  ! ${p.code}: ${p.detail}`);
  lines.push('');
});

if (isList) {
  lines.push(`Links between records: ${word[report.continuity]} (seq 1 to ${report.results.at(-1).summary.seq ?? '?'}, as presented)`);
  lines.push(`Trusted head:          ${word[report.head]}`);
  for (const p of report.linkProblems) lines.push(`  ! ${p.code}: ${p.detail}`);
  lines.push('');
}

lines.push(`RESULT: ${report.pass ? 'PASS' : 'FAIL'}`);
lines.push('');
if (report.pass) {
  lines.push('What this shows: the record' + (isList ? 's were' : ' was') + ' signed by the holder of the trusted key and');
  lines.push('not changed since. If that key is Counterroll\'s key for this organisation, this is');
  lines.push('what Counterroll recorded.');
} else {
  lines.push('What this shows: at least one record was changed after signing, was signed by a');
  lines.push('different key, or is not in the published format. Do not rely on it.');
}
lines.push('What it never shows: that the decision was correct, that any money moved (or');
lines.push('did not), or that you have every record. Completeness: not verified.');
process.stdout.write(`${lines.join('\n')}\n`);
process.exit(report.pass ? 0 : 1);
