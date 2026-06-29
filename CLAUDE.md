# CLAUDE.md

Guidance for working in this repo. Read `SURVEY.md` (why this shape) and
`ARCHITECTURE.md` (how it fits together) before changing crypto or module boundaries.

## What this is

Arkade Stealth: silent payments for Arkade VTXOs. A recipient publishes one static
meta-address; each inbound payment is unlinkable to third parties; an opt-in **view key**
gives a compliance auditor full inbound visibility with **no spend authority**.

## Toolchain — Bun only

This project uses **Bun** (no npm/node/tsx). Bun runs the TypeScript directly.

```bash
bun install          # install @noble/secp256k1 + @noble/hashes
bun run test         # -> ALL 22 CHECKS PASSED  (package.json script)
bun run demo.test.ts # same thing, direct

# NOTE: bare `bun test` invokes Bun's native runner (looks for bun:test cases)
# and finds none. The suite is a self-contained script — use `bun run test`.
```

Do not add `tsx`, `ts-node`, a `node` run step, or a bundler. Do not introduce a test
framework — `demo.test.ts` is a self-contained, top-to-bottom assert runner on purpose.

## Files

| File | Responsibility | May depend on |
|------|----------------|---------------|
| `stealth.ts` | Pure secp256k1/sha256 crypto: keys, meta-address, BIP-352 single- **and multi-input** derive, scan, spend-key, view key. **Zero SDK deps.** | noble only |
| `sidecar.ts` | `StealthScanner`: register view key → scan `ArkadeTx` (single-input, push model) → `onIncoming` → history / `rescan`. | `stealth.ts` |
| `treewalk.ts` | `StealthVtx` schema + `IndexerAdapter` + `parseTree` + `TreeScanner`: client PULLS the batch tree, scans multi-input locally, cursor + refresh dedup. The off-chain seam. | `stealth.ts` |
| `hosted.ts` | Tier-2 `HostedScanner`: `registerViewKey` + `onIncoming` webhook over a `TreeScanner`. | `treewalk.ts` |
| `resolver.ts` | `name@domain → meta-address` + BIP-353-shaped TXT record. | `stealth.ts` types |
| `demo.test.ts` | End-to-end proof (22 checks). | all of the above |

## Invariants — do not break

- **`stealth.ts` stays SDK-free and Arkade-agnostic.** It must not import Arkade tx
  formats, networking, or storage. It is auditable in isolation.
- **Detect-only is structural.** A `ViewKey` is `{ bScan, bSpendPub }` — scan secret plus
  the spend *public* key. It must never carry `b_spend`. Spend derivation
  (`recipientSpendKey`) requires `spendPriv`; the scanner never has it.
- **The math:** `P = B_spend + H( H(outpoint‖A)·a·B_scan ‖ t )·G`, and
  `p = b_spend + k (mod n)` with `p·G == P`. Sender and scanner compute the same `ecdh`
  because `a·B_scan == b_scan·A`.
- **One Arkade seam.** All live-format coupling lives in `sidecar.ts::parseIndexerTx`
  (currently a documented stub). Keep it there.
- Meta-address is hex (`encode/decodeMetaAddress`). Swapping to bech32m is a future
  change isolated to those two functions + the resolver `PARAM`.

## Conventions

- ES modules, `"type": "module"`. Intra-repo imports are **extensionless**
  (`from './stealth'`) — Bun resolves the `.ts`. Do not add `.js`/`.ts` extensions.
- Scalars are `bigint` reduced mod `n` (`_internal.modN`); pubkeys are 33-byte compressed
  hex strings; points are noble `ProjectivePoint`.
- New behavior ships with a numbered `check(...)` in `demo.test.ts`. If you change the
  count, update the final guard (`n !== 22`) and the "ALL N CHECKS PASSED" expectation.

## The one live-verify item

`sidecar.ts::parseIndexerTx` is unimplemented by design. To wire the sidecar to a live
Arkade node, confirm the indexer (`GetVirtualTxs` hex / `GetSubscription` events) exposes,
per input, the spender's `userPK`, and per output the taproot pubkey + outpoint + amount,
then map them into `ArkadeTx`. Everything else already runs against structured `ArkadeTx`.

## Next steps (tracked)

1. Implement `parseIndexerTx` against the real tx format.
2. Wire `senderDerive` into an Arkade `sendBitcoin` that funds `VTXO(P)`.
3. Build the compliance dashboard on `StealthScanner.getHistory(label)`.
