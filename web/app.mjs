// Browser page for counterroll-verify. Same engine as the command line
// (src/core.mjs); crypto comes from the browser's Web Crypto API. Makes no
// network requests (the page's CSP sets connect-src 'none').

import { VERIFIER_VERSION, hexToBytes, normalizeKey, verifyRecord, verifyRecords } from '../src/core.mjs';
import { EXAMPLE_KEY, ORIGINAL, EDITED } from './examples.mjs';

const $ = (id) => document.getElementById(id);
const subtle = globalThis.crypto && globalThis.crypto.subtle;
const toHex = (buf) => Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');

const webCrypto = {
  async sha256Hex(text) {
    return toHex(await subtle.digest('SHA-256', new TextEncoder().encode(text)));
  },
  async ed25519Verify(publicKeyHex, messageBytes, signatureHex) {
    try {
      const key = await subtle.importKey('raw', hexToBytes(publicKeyHex), { name: 'Ed25519' }, false, ['verify']);
      return await subtle.verify({ name: 'Ed25519' }, key, hexToBytes(signatureHex), messageBytes);
    } catch {
      return false;
    }
  },
};

// A browser without Ed25519 in Web Crypto must not report a signature failure
// as if the record were bad, so check support once, up front.
async function ed25519Supported() {
  if (!subtle) return false;
  try {
    await subtle.importKey('raw', hexToBytes(EXAMPLE_KEY), { name: 'Ed25519' }, false, ['verify']);
    return true;
  } catch {
    return false;
  }
}

function el(tag, attrs = {}, text) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  if (text !== undefined) n.textContent = text;
  return n;
}

const WORD = { pass: 'PASS', fail: 'FAIL', not_checked: 'not checked', not_requested: 'not requested', not_supplied: 'not supplied' };

function show(report, isList, label, key) {
  const box = $('result');
  box.replaceChildren();
  box.hidden = false;
  if (label) box.append(el('p', { class: 'muted' }, label));
  box.append(el('p', { class: `verdict ${report.pass ? 'pass' : 'fail'}` }, `RESULT: ${report.pass ? 'PASS' : 'FAIL'}`));
  box.append(el('p', { class: 'muted' }, `Trusted key: ${key.slice(0, 8)}…${key.slice(-4)}`));
  report.results.forEach((r, i) => {
    const s = r.summary;
    const rows = el('div', { class: 'row' });
    const add = (k, v) => { rows.append(el('span', {}, k), el('span', {}, v)); };
    if (isList) add('Record', `${i + 1} of ${report.results.length}`);
    add('Says', s.decision ? `${s.decision}${s.denyReasons && s.denyReasons.length ? ` (${s.denyReasons.join(', ')})` : ''}` : '?');
    add('Amount', s.amount ? `${s.amount} atomic units${s.perTxCap ? `, cap ${s.perTxCap}` : ''}` : '?');
    add('Payee', s.payTo ?? '?');
    add('Agent', s.agentId ?? '?');
    add('Organization', s.organizationId ?? '?');
    add('Seq', s.seq ?? '?');
    add('Format', `${WORD[r.checks.format]}${s.form ? ` (${s.form})` : ''}`);
    add('Content', r.checks.content === 'pass' ? 'PASS, matches the signed hash' : r.checks.content === 'fail' ? 'FAIL, does not match the signed hash: changed after signing' : WORD[r.checks.content]);
    add('Signature', r.checks.signature === 'pass' ? 'PASS, the stored hash was signed by the trusted key' : WORD[r.checks.signature]);
    const wrap = el('div', { style: i ? 'margin-top:1rem;border-top:1px solid var(--rule);padding-top:1rem' : '' });
    wrap.append(rows);
    for (const p of r.problems) wrap.append(el('p', { class: 'problem' }, `${p.code}: ${p.detail}`));
    box.append(wrap);
  });
  if (isList) {
    box.append(el('p', { style: 'margin-top:1rem' }, `Links between records: ${WORD[report.continuity]}`));
    for (const p of report.linkProblems) box.append(el('p', { class: 'problem' }, `${p.code}: ${p.detail}`));
  }
  box.append(el('p', { style: 'margin-top:1rem' }, report.pass
    ? 'This shows the record was signed by the holder of the trusted key and not changed since. If that key is Counterroll\'s key for this organization, this is what Counterroll recorded.'
    : 'At least one record was changed after signing, was signed by a different key, or is not in the published format. Do not rely on it.'));
  box.append(el('p', { class: 'muted', style: 'margin-bottom:0' }, 'It never shows that the decision was correct, that any money moved (or did not), or that you have every record. Completeness: not verified.'));
}

function showError(message) {
  const box = $('result');
  box.replaceChildren(el('p', { class: 'fail' }, message));
  box.hidden = false;
}

let supported;
async function run(input, keyText, label) {
  if (supported === undefined) supported = await ed25519Supported();
  if (!supported) {
    showError('This browser cannot check Ed25519 signatures, so it cannot give a result. Use a current browser or the command line version.');
    return;
  }
  const key = normalizeKey(keyText);
  if (!key) { showError('The key must be 64 hex characters (a 32-byte Ed25519 public key).'); return; }
  const isList = Array.isArray(input);
  if (isList && input.length === 0) { showError('The list is empty.'); return; }
  const report = isList
    ? await verifyRecords(input, { publicKey: key, crypto: webCrypto })
    : await (async () => {
        const r = await verifyRecord(input, { publicKey: key, crypto: webCrypto });
        return { pass: r.pass, results: [r], continuity: 'not_checked', linkProblems: [] };
      })();
  show(report, isList, label, key);
  $('result').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

$('tool-version').textContent = VERIFIER_VERSION;
$('example-key').textContent = EXAMPLE_KEY;
$('try-original').addEventListener('click', () => run(ORIGINAL, EXAMPLE_KEY, 'Example: the original refusal (DENY, 9.00 against a 5.00 cap)'));
$('try-edited').addEventListener('click', () => run(EDITED, EXAMPLE_KEY, 'Example: the edited copy (DENY changed to APPROVE)'));
$('check').addEventListener('click', () => {
  let input;
  try {
    input = JSON.parse($('record').value);
  } catch (e) {
    showError(`The record is not valid JSON: ${e.message}`);
    return;
  }
  run(input, $('key').value);
});
$('pick').addEventListener('change', async (e) => {
  const f = e.target.files && e.target.files[0];
  if (f) $('record').value = await f.text();
});
