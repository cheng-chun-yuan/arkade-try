# Architecture — Arkade Stealth

## 1. Actors & trust boundaries

```
┌──────────┐   meta-addr (public)   ┌──────────────┐
│  Sender  │ ◀───── resolve ─────── │   Resolver   │  treasury@arkade.btc → (B_scan, B_spend)
│  holds a │                         └──────────────┘
└────┬─────┘
     │ spends VTXO(a), derives P, funds VTXO(P)        ── operator co-signs P as a normal userPK
     ▼
┌─────────────────────────────────────────────┐
│ Arkade operator  (sees the offchain tx graph)│
└───────────────┬─────────────────────────────┘
                │ streams txs (auth-gated)
                ▼
┌──────────────────────────────┐    delegated VIEW KEY     ┌───────────────┐
│ StealthScanner / Auditor     │ ◀──── b_scan + B_spend ── │   Recipient   │
│ DETECTS all inbound          │                            │ b_scan+b_spend│
│ CANNOT spend                 │ ── onIncoming(P,amount) ─▶ │ derives p,    │
└──────────────────────────────┘                            │ spends VTXO(P)│
                                                            └───────────────┘
```

**Trust boundaries**
- Sender ⟷ third parties: payments are **unlinkable** (different P per payment).
- Scanner/Auditor: trusted to **see** inbound (holds `b_scan`), structurally unable to
  **spend** (no `b_spend`). Compromise leaks privacy, never funds.
- Operator: co-signs; sees the tx graph (its existing privilege). Does not learn that
  `P` is stealth-derived.

## 2. Capability model (who holds what)

| Capability | Sender | Scanner / Auditor | Recipient | Operator |
|---|---|---|---|---|
| Resolve meta-address | ✅ | – | – | – |
| Derive `P` (fund) | ✅ | ✅ (detect) | ✅ | ❌ |
| Detect inbound | – | ✅ | ✅ | ✅ (graph) |
| Derive `p` (spend) | ❌ | **❌** | ✅ | ❌ |
| Link payments to one recipient | ❌ | ✅ (by design) | ✅ | ✅ (graph) |

The single load-bearing invariant: **`p = b_spend + k` requires `b_spend`, which the
view key does not contain.** Detect-only falls out of the math.

## 3. Module boundaries

| Module | Owns | Depends on | Must NOT |
|---|---|---|---|
| `stealth.ts` | all secp256k1/sha256 crypto: keys, meta-addr, derive, scan, spend-key, view key | noble only | know about Arkade tx formats, networking, or storage |
| `sidecar.ts` | `StealthScanner`: register view key → scan `ArkadeTx` → `onIncoming` → history / `rescan` | `stealth.ts` | hold any spend secret; depend on a concrete indexer until `parseIndexerTx` |
| `resolver.ts` | `name@domain` → meta-address + BIP-353-shaped TXT record | `stealth.ts` types | derive keys or scan |
| `demo.test.ts` | end-to-end proof (13 checks) | all of the above | — |

`stealth.ts` is a pure crypto core with **zero SDK deps**, so it is auditable in
isolation and reusable outside Arkade. Everything Arkade-specific is quarantined to the
one documented `parseIndexerTx` seam.

## 4. Data shapes (the integration contract)

```ts
ArkadeTx {
  txid: string
  inputs:  { userPK: string /*A, compressed hex*/, outpoint: {txid, vout} }[]
  outputs: { pubkey: string /*P, compressed hex*/, amount: number, vout: number }[]
}
```

`parseIndexerTx(raw) -> ArkadeTx` is the **only** place that touches the live Arkade
format. If the indexer exposes per-input `userPK` and per-output `(pubkey, outpoint,
amount)` — which it should, since `userPK` is revealed in the spend witness — the sidecar
drives straight off the live stream. If not, it still runs against the operator's own tx
store in regtest. This is the single live-verify item.

## 5. Core flows

**Send.** resolve → `senderDerive({meta, a, spentOutpoint, t})` → `P` → fund `VTXO(P)`;
operator co-signs `P` as `userPK`.

**Detect.** operator streams tx → `scanner.scanTx(tx)` tries each output as a payment
from `input[0]` for every registered view key → match → `onIncoming` + append history.

**Spend.** recipient takes `derivation` from the detected payment →
`recipientSpendKey({b_scan, b_spend, A, spentOutpoint, t})` → `p` with `p·G == P` → spends.

**Recover / onboard auditor.** `scanner.rescan(allTxs)` replays the stream from scratch;
combined with `recipientFromSeed`, inbound is fully recoverable from a seed + the tx
stream — no extra stored state.

## 6. Decisions & rationale (forced by Arkade — see SURVEY.md)

1. Secret derived from `A` + outpoint already in the tx → **no extra broadcast**.
2. Detection via a sidecar holding a delegated view key → honest model of who can see an
   auth-gated tx graph.
3. View key == audit key → detection and compliance are one primitive.
4. `P` plugs in as `userPK` → **operator unchanged**.

## 7. Non-goals for v0

Multi-input aggregation, amount confidentiality, hiding the operator's graph view, and
bech32m meta-address encoding are explicitly out of scope and tracked as future work.
