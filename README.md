# Arkade Stealth — silent payments for VTXOs (hackathon v0)

Reusable address with **per-payment unlinkability** on Arkade, plus an **opt-in view key**
that gives a compliance auditor full visibility into one entity's inbound — without the
ability to spend.

```
treasury@arkade.btc                     <- static name (BIP-353-shaped resolver)
        │  resolve
        ▼
  meta-address (B_scan, B_spend)         <- published once, never changes
        │
        ▼  sender spends a VTXO; derives from ITS OWN input key (silent-payment style)
  P = B_spend + H( H(outpoint‖A)·a·B_scan ‖ t )·G
        │  fund VTXO(P) — operator co-signs P like any normal userPK
        ▼
  StealthScanner (holds delegated view key b_scan)   <- detects all inbound, CANNOT spend
        │  onIncoming(P, amount)
        ▼
  recipient derives p = b_spend + k  (p·G == P) and spends
```

## Docs

- **`PRODUCT.md`** — what it is, who it's for, differentiators, roadmap.
- **`SURVEY.md`** — the primitive landscape and why Arkade forces this exact shape.
- **`ARCHITECTURE.md`** — actors, trust boundaries, capability model, module contracts.
- **`CLAUDE.md`** — working agreement for this repo (Bun-only, invariants, conventions).

## Files

| File | What it is |
|------|------------|
| `stealth.ts` | Pure secp256k1 crypto: keys, meta-address, BIP-352 single-input derivation, scan, spend-key, view key. Zero SDK deps. |
| `sidecar.ts` | `StealthScanner`: register view key → scan Arkade txs → `onIncoming` → history / `rescan` for seed recovery. |
| `resolver.ts` | Static `name@domain → meta-address` lookup + BIP-353-shaped TXT record. |
| `demo.test.ts` | End-to-end proof (13 checks). |

## Run (Bun only)

```bash
bun install
bun run test    # -> ALL 13 CHECKS PASSED   (also: bun run demo.test.ts)
```

## The one thing to verify live (regtest)

The crypto and scan logic are proven here against structured `ArkadeTx` objects. The
remaining integration check is `sidecar.ts::parseIndexerTx`: confirm the Arkade indexer
(`GetVirtualTxs` hex / `GetSubscription` events) exposes, per input, the spender's
`userPK`, and per output the taproot pubkey + outpoint + amount, then implement it.

## Scope (v0) and honesty notes

- **Single-input** silent payment (no multi-input aggregation). Keeps the input-hash
  tweak for replay protection.
- Unlinkable to third parties; the sidecar/auditor *can* link inbound (by design) but
  **cannot spend**.
- **Not** hidden: amounts, and the operator's privileged transaction-graph view.
- Meta-address is hex-encoded; swap for bech32m before any real use.
