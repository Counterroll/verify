# Counterroll record verifier

Check a Counterroll decision record yourself, offline, without asking
Counterroll.

Counterroll checks AI agents' x402 payment requests against spending rules
and writes a signed record of each APPROVE or DENY it decides. This tool
checks that such a record was signed by the key you trust and has not been
changed since. It is free, open source (MIT), needs only Node.js 18 or later,
has no dependencies, and makes no network connection.

This is not the x402 setup checker at counterroll.dev/check. That one
looks at your project's x402 settings. This one checks signed records.

## What verification means

In plain words: someone can check that a record came from Counterroll and
was not edited, without having to ask us.

The example in this repository: an agent asks to spend 9.00 against a
5.00 per-payment cap. Counterroll records "DENY: over the cap" and signs it.
A reviewer runs the verifier with Counterroll's trusted public key. The
original passes. Change "DENY" to "APPROVE" and the edited copy fails.

Think of it like a tamper-evident seal on a receipt. It proves what
Counterroll recorded, not that the decision was correct or that money moved.

## Try it

```
git clone https://github.com/Counterroll/verify
cd verify

node bin/counterroll-verify.mjs examples/refusal-original.json \
  --key ab0aba4ac25570cf8c0b27a729fb47923461c9f9be7c3e60a982857685f8586c

node bin/counterroll-verify.mjs examples/refusal-edited.json \
  --key ab0aba4ac25570cf8c0b27a729fb47923461c9f9be7c3e60a982857685f8586c
```

The first ends with `RESULT: PASS` (exit code 0). The second ends with
`RESULT: FAIL` and `hash_mismatch` (exit code 1): its content no longer
matches the hash Counterroll signed. Its signature line still says PASS,
because the signature over the original hash is intact; what fails is the
link between that hash and the edited content. Re-computing the hash to
match the edit would break the signature instead, and making a new signature
needs the private key.

After cloning you can disconnect from the network; nothing else is needed.

## Which public key to trust

The verifier never reads a key from the file it checks. You must supply it
with `--key`, and it must reach you by a route other than the records. A key
that arrives with the records proves nothing: whoever edited the records
could replace the key too, and a forged record re-signed with a made-up key
passes when checked against that made-up key.

**For the two examples in this repository** the key is:

```
ab0aba4ac25570cf8c0b27a729fb47923461c9f9be7c3e60a982857685f8586c
```

It belongs to `org_sample_verify`, a fictional organization made up for this
sample. Counterroll publishes it in two places so you can compare them: this
README and counterroll.dev/verify. Both are run by Counterroll, so a match
shows only that this is the key Counterroll publishes for the sample. The
private half was held in memory while the sample was generated and was never
written to disk by the generator, so it is not available to sign further
records.

**For real records** each organization that uses Counterroll has its own
signing key. Get your organization's public key from Counterroll when you set
up, by a route you choose, separate from where you later receive records.
Write it down, and use that same key every time you verify. If someone else
(an auditor, a counterparty) needs to check your records, give them the key
by a route they trust, not attached to the records.

## What a PASS proves, and what it does not

| A PASS shows | A PASS does not show |
|---|---|
| The record was signed by whoever holds the private half of the key you supplied | That the key is Counterroll's, unless you got it by a route you trust |
| None of the signed fields (decision, reasons, amount, payee, agent, policy, time, chain link) changed since signing | That the decision was correct or the policy was right |
| The record is in the published format (`FORMAT.md`) | That any money moved, or did not move |
| For a list: the records presented link up from record 1 | That you have every record; with `--head` it shows the list ends where you expect |

Every report says `Completeness: not verified`.

Some requests never get a signed record. Requests refused before the policy
check (an unknown agent, a malformed message, a repeated payment, and in one
configuration a missing or invalid payer signature) leave an unsigned event or
nothing. A missing record is not proof that no request or payment happened.

## Usage

```
counterroll-verify <record.json> --key <public-key-hex> [--org <id>] [--head <seq>:<hash>] [--json]
```

| Input | Checked as |
|---|---|
| One record (a JSON object) | That record: format, content against hash, signature |
| A JSON array of records | Each record, then the links, as an organization's chain starting at seq 1 |

| Option | Meaning |
|---|---|
| `--key <hex>` | The Ed25519 public key you trust (64 hex characters). Required |
| `--org <id>` | Fail unless every record belongs to this organization |
| `--head <seq>:<hash>` | A last record you already trusted. Fails if the list ends anywhere else |
| `--json` | Machine-readable output |

| Exit code | Meaning |
|---|---|
| 0 | PASS |
| 1 | FAIL |
| 2 | Could not run: bad arguments, or a file that is missing or not JSON. Not a verdict |

The engine is also importable: `verifyRecord(record, { publicKey })` and
`verifyRecords(records, { publicKey, head })` in `src/verify.mjs`.

## The format

`FORMAT.md` specifies the record: every field, the canonical JSON rules with
test vectors, the hash and signature, the chain, and which forms a verifier
accepts. It is Counterroll's own format, published so anyone can implement a
verifier. It is not an industry standard.

## Limits, stated plainly

- The verifier was written by Counterroll, the same party that produces the
  records. It has not been independently audited. It is short; read
  `src/verify.mjs` before relying on it.
- It checks decision records only. It does not check authorization bindings,
  the payer's own payment signature (which a decision record does not
  contain), unsigned refusal events, or settlement.
- The two examples are fictional: a made-up organization, agent, payee and
  token on a test network (`eip155:84532`). They were produced by Counterroll's
  real request handler running against an in-memory store, not a database.
- Counterroll supports one signing key per organization today; there is no
  key rotation yet.

## Verification is free. Evaluation is the paid part.

Anyone can verify Counterroll records with this tool at no cost. If you want
to know how Counterroll's policy checks would handle your own agent payment
scenarios, Counterroll offers a paid offline evaluation: we run your
scenarios on synthetic data and give you the signed records, edited copies
and a written report. Write to hello@counterroll.dev.

## Tests

```
node --test test/*.test.mjs
```

## Licence

MIT. See `LICENSE`.
