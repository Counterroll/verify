# Counterroll decision record format

Document date: 2026-11-22. Verifier: `counterroll-verify` 0.1.0.

This is Counterroll's own record format, published so that anyone can check a
Counterroll record without asking Counterroll. It is not an industry standard
and no other party has adopted it. It describes what Counterroll's code
writes today; it does not describe planned work.

## 1. What a decision record is

When an agent's x402 payment request reaches Counterroll's policy check,
Counterroll decides APPROVE or DENY and writes one **decision record**
(internally called an attestation). The record says which agent asked, what
it asked to pay, which policy applied, the decision and the reasons. It is
hashed, signed with the organization's Ed25519 key, and linked to the
organization's previous record.

**Not every request gets a signed record.** Requests refused before the
policy check (for example an unknown agent, a malformed message, a repeated
payment, or in one configuration a missing or invalid payer signature) leave
an unsigned event or nothing at all. Refusals by the payment facilitator at
settlement time leave no signed decision record. A missing record is not
proof that no request or payment happened.

**A decision record says nothing about settlement.** Counterroll does not
move money. An APPROVE means Counterroll's policy allowed the request; it
does not mean a payment happened. A DENY means Counterroll refused it; on
its own it does not show what happened on the payment rail.

## 2. Example

The refusal in `examples/refusal-original.json` (fictional data): an agent
asked to pay 9.00 of a synthetic 6-decimal token (`9000000` atomic units)
against a 5.00 per-payment cap (`5000000`), and Counterroll refused it with
`per_tx_cap_exceeded`.

```json
{
  "id": "att_1a47920b4d5e74e1b44d79284bfa9ad2",
  "organizationId": "org_sample_verify",
  "seq": "2",
  "agentId": "agent_sample_buyer_verify",
  "policyId": "policy_sample_verify",
  "decision": "DENY",
  "denyReasons": ["per_tx_cap_exceeded"],
  "network": "eip155:84532",
  "asset": "0x5a5a…5a5a",
  "payTo": "0xa1a1…a1a1",
  "amount": "9000000",
  "eip3009Nonce": "fa42…3dc5",
  "payloadSha256": "2fbb…f680",
  "requirements": { "scheme": "exact", "amount": "9000000", "…": "…" },
  "policySnapshot": { "perTxCap": "5000000", "windowCap": "20000000", "…": "…" },
  "attestationType": null,
  "schemaVersion": null,
  "prevHash": "fcf773e1…ec24",
  "hash": "02c10e5c…dd5d",
  "signature": "2580282f…a60f",
  "createdAt": "2026-11-15T15:01:00.000Z"
}
```

(Values shortened here; the file has them in full.)

## 3. Fields

A record is a JSON object with exactly these fields. A verifier MUST reject a
record with any other field, because an extra field is not covered by the
signature and could claim anything.

### 3.1 Signed fields (17, always present)

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Record identifier. |
| `organizationId` | string | The organization (Counterroll customer) the record belongs to. Each organization has its own key and its own chain. |
| `seq` | string of digits | Position in the organization's chain, starting at `"1"`. |
| `agentId` | string | The agent the request was attributed to. |
| `policyId` | string or null | The policy applied; null when no policy applied (which is a DENY). |
| `decision` | `"APPROVE"` or `"DENY"` | Counterroll's decision. |
| `denyReasons` | array of strings | Machine-readable reasons; empty on APPROVE. See §3.4. |
| `network` | string | CAIP-2 network of the requested payment, for example `eip155:8453`. |
| `asset` | string | Token of the requested payment. |
| `payTo` | string | Payee of the requested payment. |
| `amount` | string of digits | Requested amount in the token's smallest unit. Never a JSON number. |
| `eip3009Nonce` | string | Nonce of the payer's payment authorization, normalized. |
| `payloadSha256` | string | SHA-256 of the x402 payment payload as Counterroll received it. |
| `requirements` | object | The x402 `PaymentRequirements` the request was evaluated against, as received. |
| `policySnapshot` | object or null | The policy rules exactly as applied, or null when none applied. |
| `prevHash` | string | `hash` of the organization's previous record, or `"GENESIS"` for record 1. |
| `createdAt` | string | ISO-8601 UTC time with milliseconds, from Counterroll's clock. |

### 3.2 Form fields

| Field | Type | Meaning |
|---|---|---|
| `attestationType` | string or null | Which form the record is in. See §5. |
| `schemaVersion` | number or null | Same. |

Either field may also be absent, which means null.

### 3.3 Envelope fields (not signed themselves)

| Field | Type | Meaning |
|---|---|---|
| `hash` | 64 lowercase hex | SHA-256 of the record's canonical preimage (§6). |
| `signature` | 128 lowercase hex | Ed25519 signature over the 32 raw bytes of `hash` (§6). |

### 3.4 Deny reasons

`per_tx_cap_exceeded`, `window_cap_exceeded`, `payee_not_allowed`,
`network_not_allowed`, `asset_not_allowed`, `stale_authorization`,
`wallet_mismatch`, `agent_suspended`, `no_policy`, `agent_unknown`, `replay`,
`malformed`. The first nine come from the policy check. The last three are
normally refused before the policy check and then leave an unsigned event,
not a signed record. A verifier treats the reasons as signed text; it does
not judge them.

## 4. Canonical JSON

The hash is computed over a canonical serialization, so two independent
implementations produce identical bytes:

1. Object keys are sorted in ascending order by UTF-16 code unit, exactly
   like JavaScript's `Object.keys(obj).sort()`. This is not UTF-8 byte order;
   they differ for characters at or above U+10000. Sorting applies at every
   level, including objects inside arrays.
2. No whitespace anywhere.
3. Strings are escaped exactly as JavaScript's `JSON.stringify` does: `"` and
   `\` are escaped, `\b \f \n \r \t` use their short forms, other characters
   below U+0020 become `\u00XX`, and everything else, including non-ASCII, is
   written as is and encoded as UTF-8.
4. No Unicode normalization is applied to keys or values.
5. Numbers must be safe integers (magnitude at most 2^53 − 1) and are written
   as plain decimal digits. `-0` is written as `0`. Any other number is an
   error; amounts are always strings.
6. `null`, `true` and `false` are written as is. Arrays keep their order.
7. `undefined` and big integers are errors, never silently dropped.

### 4.1 Test vectors

Outputs are given as UTF-8 hex. A conformant implementation reproduces them
exactly. These are checked by `test/verify.test.mjs`.

| Input (JavaScript notation) | Canonical output, UTF-8 hex |
|---|---|
| `{ b: 1, a: 2, c: 3 }` | `7b2261223a322c2262223a312c2263223a337d` |
| `{ "\u{10000}": "supp", "￿": "bmp" }` | `7b22f0908080223a2273757070222c22efbfbf223a22626d70227d` |
| `{ s: "a\"b\\c\nd\u0001f" }` | `7b2273223a22615c22625c5c635c6e645c753030303166227d` |
| `{ s: "é" }` | `7b2273223a22c3a9227d` |
| `{ s: "é" }` | `7b2273223a2265cc81227d` |
| `{ n: -0 }` | `7b226e223a307d` |
| `{ arr: [1, null, true, false, "x"] }` | `7b22617272223a5b312c6e756c6c2c747275652c66616c73652c2278225d7d` |
| `{ z: [{ y: 1, x: 2 }], a: "end" }` | `7b2261223a22656e64222c227a223a5b7b2278223a322c2279223a317d5d7d` |
| `{ a: undefined }`, `{ a: 10n }`, `{ a: 1.5 }`, `{ a: 9007199254740992 }` | error |

## 5. Forms

A verifier resolves the form from `attestationType` and `schemaVersion`. The
set is closed: anything else is rejected, whether or not the signature
verifies.

| `attestationType` | `schemaVersion` | Form | Preimage |
|---|---|---|---|
| null or absent | null or absent | **Untyped form.** What Counterroll writes by default today. | The 17 signed fields. |
| `"com.counterroll.attestation"` | `2` | **Typed form, schema 2.** Supported by writer and verifier, not yet the default. | The 17 signed fields plus `"type": "com.counterroll.attestation"` and `"schemaVersion": 2`. |
| anything else, including only one of the two set | | Rejected | |

Note the typed form's preimage uses the key `type`, not `attestationType`.
The form of an existing record never changes. A future form is added to this
table; it does not change how older records are checked.

## 6. Hash and signature

```
preimage  = the 17 signed fields (plus type and schemaVersion for the typed form)
hash      = lowercase hex of SHA-256( UTF-8( canonicalJson(preimage) ) )
signature = lowercase hex of Ed25519-sign( organization private key, raw 32 bytes of hash )
```

The signature is over the hash bytes, not over the hex text. `hash` and
`signature` are never part of the preimage.

A record passes when, and only when:

1. it has exactly the fields in §3 with the right types;
2. its form resolves (§5);
3. the hash recomputed from its preimage equals `hash`; and
4. `signature` verifies over `hash` with **a public key the verifier already
   trusts** (§8).

Changing any signed field breaks step 3. Re-computing the hash after an edit
breaks step 4, because a new signature needs the private key.

## 7. Chain

Each organization's records form one chain:

- `seq` starts at `"1"` and goes up by one with no gaps.
- Record 1 has `prevHash` = `"GENESIS"`; every later record has `prevHash`
  equal to the previous record's `hash`.

Given a list of records, a verifier checks each one (§6) and then the links.
That shows the records **presented** link up correctly ("presented-chain
continuity"). It cannot show that nothing was left off the end: a chain with
its newest records removed still links up. To notice that, compare the last
record with a last record you already trusted (`--head`). No Counterroll
record or verifier claims a chain is complete.

## 8. Which key to trust

Each organization's records are signed with that organization's own Ed25519
key. The verifier needs the matching public key, and **it must reach you by a
route other than the records**. A key that arrives in the same file, folder,
email or server response as the records proves nothing: whoever edited the
records could replace the key too. See the README for the key of the
published examples and how to obtain the key for real records.

A pass shows the record was signed by whoever holds the private half of the
key you supplied. It shows the record came from Counterroll only to the extent
you trust that the key is Counterroll's key for that organization.

Signing-key rotation is not supported today: an organization has one signing
key. Re-encrypting the stored private key under a new storage key does not
change the public key.

## 9. Out of scope

Not covered by this document or checked by `counterroll-verify`:

- authorization bindings (a separate signed statement tying an approval to
  exact payment terms);
- the payer's own payment signature, which a decision record does not
  contain;
- unsigned refusal events;
- reconciliation findings and settlement records;
- whether a payment settled on any chain.
