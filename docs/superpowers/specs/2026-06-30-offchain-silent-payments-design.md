# Off-chain silent payments via client-side batch-tree scanning

**Date:** 2026-06-30
**Status:** Approved design → implementation

## Problem

BIP-352 silent payments assume a **public, enumerable on-chain UTXO set**: globally
unique outpoints, taproot output keys anyone can read, single-spend enforced by consensus.
Arkade has none of that natively — VTXOs are **off-chain** virtual TXOs co-signed by an
operator and arranged in a batch/round tree, and the tx graph is auth-gated
(`GetVirtualTxs`), not public.

The recipient wants to **pull the full batch tree from the indexer and scan it
client-side with a view key**, with the view key never leaving the device. We also want a
lightweight integration surface so other services can send to, or detect for, stealth
addresses.

This spec answers two questions:
1. What schema makes BIP-352 work off-chain?
2. How does a client fetch the tree and scan it locally, without ever holding spend
   authority?

## Topology & trust

The recipient's own wallet pulls the batch tree from the indexer and scans **locally**.
The view key (`bScan`, `bSpendPub`) never leaves the device. No blockchain is in the path;
the auth-gated indexer is the source of truth.

```
indexer ──Get(batch tree)──▶ [client] treewalk.ts ──StealthVtx[]──▶ multi-input scan ──▶ history (local)
                                                          ▲
                                              view key (local, never sent)
```

Compromise of the device leaks the view key (privacy), never spend authority — the
load-bearing invariant `p = b_spend + k` still requires `b_spend`, which a `ViewKey`
structurally does not contain.

## The new schema — what makes BIP-352 work off-chain

BIP-352 consumes four commitments. Arkade already produces all of them; they just need to
be surfaced per tree node to an authenticated view-key holder. We call the surfaced node a
**stealth-scannable virtual tx**:

```ts
StealthVtx {
  batchId: string                                          // round/batch = scan cursor
  vtxId:   string                                          // tx boundary / dedup key
  inputs:  { userPK: string; vtxoId: string }[]            // userPK = Aᵢ ; vtxoId = replay nonce
  outputs: { userPK: string; amount: number; leafIndex }[] // userPK = P  ; leafIndex = BIP-352 counter t
}
```

| BIP-352 needs | On-chain source | Arkade-native equivalent |
|---|---|---|
| Spender pubkeys `Aᵢ` → `A_sum` | input witness pubkeys | `userPK` revealed when a VTXO is spent (co-sign witness) |
| A unique replay nonce | globally-unique UTXO outpoint | **`vtxoId`** — canonical id of the *spent* VTXO; unique because the operator enforces single-spend |
| Output key `P` to test | taproot scriptPubKey | `userPK` of the newly created VTXO leaf |
| amount | `TxOut.value` | leaf VTXO amount |
| tx boundary (group in↔out) | the transaction | one virtual-tx node in the batch tree |

**The one conceptual substitution:** `vtxoId` replaces the on-chain outpoint as the
`input_hash` nonce. Nothing on-chain is required — only that the batch-tree schema surface
these fields.

## Cryptographic core — single-input → multi-input (BIP-352 aggregation)

A batch tree has many inputs per virtual tx, so the scan core generalizes from
single-input v0 to BIP-352 multi-input aggregation:

```
A_sum      = Σ Aᵢ                       (sum of input pubkeys as curve points)
a_sum      = Σ aᵢ  (mod n)              (sender side; sum of input secrets)
nonce      = min(vtxoId over inputs)     (lexicographically smallest)
input_hash = H( nonce ‖ A_sum )
ecdh       = input_hash · a_sum · B_scan          (sender)
           = input_hash · b_scan · A_sum          (scanner / recipient)   [equal]
k          = H( ecdh ‖ t )               (t = output leafIndex)
P          = B_spend + k·G
p          = b_spend + k  (mod n)        with p·G == P
```

Single-input v0 is exactly the `n = 1` case, so the existing 13 checks remain valid and
untouched. New multi-input functions are added alongside the existing ones:
`sumPubkeys`, `senderDeriveMulti`, `expectedPMulti` / `scanMatchesMulti`,
`recipientSpendKeyMulti`. `stealth.ts` stays SDK-free.

## Modules

| Module | Change | Responsibility | May depend on |
|---|---|---|---|
| `stealth.ts` | **upgrade** | adds multi-input BIP-352 aggregation; still pure crypto | noble only |
| `treewalk.ts` | **new** | `StealthVtx` schema, `IndexerAdapter`, `parseTree`, `TreeScanner` (cursor + history + refresh dedup). The sole Arkade-format seam, client-side. | `stealth.ts` |
| `hosted.ts` | **new** | Tier-2 `HostedScanner`: `registerViewKey` + `onIncoming` webhook over a `TreeScanner`. Transport-agnostic (HTTP binding is the deployment skin). | `treewalk.ts` |
| `sidecar.ts` | keep | legacy single-input `StealthScanner` (push model) unchanged | `stealth.ts` |
| `resolver.ts` | keep | `name@domain → meta-address` (Tier-0 senders use it) | `stealth.ts` types |

`parseTree` is the relocated `parseIndexerTx` seam: the only place that touches the live
Arkade batch-tree format. Everything downstream runs on structured `StealthVtx`.

## Data flow (recipient self-scan)

1. `adapter.fetchBatches(cursor)` → raw batch tree(s) since the stored cursor.
2. `parseTree(raw)` → `StealthVtx[]`.
3. Per vtx: aggregate inputs → `A_sum`, `nonce = min(vtxoId)`; scan each output `P` with
   `t = leafIndex` via `scanMatchesMulti`.
4. Match → `IncomingPayment` appended to local history; `onIncoming` fires.
5. Advance cursor; persist `{ cursor, history, knownP }` locally.

## Incremental vs recovery

- **Steady state:** `sync()` pulls batches after `cursor` (round id / batch height) and
  appends. Cheap, O(new batches).
- **Recovery / fresh device:** `rescan()` from genesis reproduces all inbound from
  **seed + indexer alone** — no other stored state. `sync()` accumulated == `rescan()`
  is an explicit test invariant.

## Refresh / self-spend (the off-chain wrinkle)

Arkade VTXOs expire and must be refreshed (the recipient re-anchors `P` into a new batch
before expiry). On refresh, `P` appears as an **input** `userPK` and as a renewed
**output** `userPK` in a later batch. Handling is a **dedup rule, not a schema change**:

- The scanner keeps `knownP` (set of detected `P`s) per label.
- An output whose `userPK ∈ knownP` is a **renewal** → update that payment's `batchId`,
  do **not** emit a new inbound.
- An input whose `userPK ∈ knownP` is a corroborating **self-spend** signal.

Detection stays idempotent across renewals.

## Error handling & edges

- Indexer unreachable / partial tree → fail closed, keep last good cursor, retry; never
  advance the cursor past a gap.
- Malformed tree node → skip that vtx, continue (one bad batch ≠ stalled scan).
- Reorg / batch rollback → rewind cursor to last stable round.
- `t` is the deterministic `leafIndex` (no unbounded counter loop); work per vtx is bounded.

## Integration tiers (lightweight surface for other services)

One scan core, three skins, lightest → heaviest effort, with an explicit privacy gradient:

| Tier | For | Ships | View key location | Effort |
|---|---|---|---|---|
| **0 — Sender SDK** | wallets/PSPs paying a stealth addr | `stealth.ts` + `resolver.ts` (zero-dep) | none (sender holds none) | `resolve → senderDeriveMulti → fund VTXO(P)` |
| **1 — Detect adapter** | custodial wallets/exchanges/auditors | `TreeScanner` + `IndexerAdapter` interface | in integrator's process (detect-only) | implement `fetchBatches(cursor)` |
| **2 — Hosted scan API** | services wanting zero infra | `HostedScanner` (REST `registerViewKey` + webhook) | leaves integrator → reaches host (detect-only, **no spend**) | one POST + a webhook endpoint |

- **One core, three skins.** Tiers 1 and 2 are the same multi-input engine; Tier 2 wraps
  Tier 1 in a service. No forked crypto.
- **Privacy gradient is explicit.** Tier 0 leaks nothing; Tier 1 keeps the key local;
  Tier 2 trades privacy for convenience — and even a fully-compromised Tier 2 cannot spend
  (`ViewKey` is structurally `{ bScan, bSpendPub }`).
- **Stable contracts.** Integrators bind to `StealthVtx`, `IndexerAdapter`, and
  `IncomingPayment` — never to `stealth.ts` internals or a live Arkade format.

## Testing

Extend the self-contained `demo.test.ts` runner with numbered checks (bump the final
guard from 13):

1. multi-input `A_sum` sender/scanner round-trip
2. multi-input recipient derives `p` with `p·G == P`
3. `leafIndex` (t) distinguishes two outputs to the same recipient in one tx; both detected
4. `parseTree` fixture → `StealthVtx[]`
5. `TreeScanner.sync` detects inbound and advances the cursor
6. incremental `sync` accumulation == full `rescan`
7. refresh: renewed `P` emits no new inbound and updates `batchId`
8. Tier-2 hosted: `registerViewKey` → webhook fires `onIncoming`
9. view key still cannot derive `p` (structural)

## Non-goals (unchanged)

Amount confidentiality, hiding the operator's graph view, bech32m meta-address encoding.
**Newly in scope:** multi-input aggregation (forced by the tree substrate).
