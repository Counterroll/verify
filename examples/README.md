# Examples

Two fictional records. Everything in them is made up: the organization
`org_sample_verify`, its agent, payee and token ("Synthetic USD", 6 decimals)
on test network `eip155:84532`. No real company, person, wallet, token or
payment.

| File | What it is | Expected result |
|---|---|---|
| `refusal-original.json` | The agent asked to pay `9000000` (9.00) against a per-payment cap of `5000000` (5.00). Counterroll refused it: `DENY`, `per_tx_cap_exceeded`. This is record 2 of the sample organization's chain, as Counterroll's request handler produced it. | PASS |
| `refusal-edited.json` | The same record with `decision` changed to `APPROVE` and `denyReasons` emptied. Nothing else changed, including the hash and signature. | FAIL, `hash_mismatch` |

The key to check them with is in the top-level README, not in this folder,
on purpose: a key that sits next to the records it checks is not a reason to
trust it.

```
node bin/counterroll-verify.mjs examples/refusal-original.json --key <key from README>
node bin/counterroll-verify.mjs examples/refusal-edited.json --key <key from README>
```

The records carry a fictional clock (2026-11-15) and were produced by Counterroll's
real `/v1/attest` request handler running against an in-memory store, not a
database. Database rules (records cannot be edited or deleted) were not
exercised.
