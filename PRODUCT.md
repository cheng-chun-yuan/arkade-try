# PRODUCT.md — Arkade Stealth

Reusable address with **per-payment unlinkability** on Arkade, plus an **opt-in view key**
that gives a compliance auditor full visibility into one entity's inbound — without the
ability to spend.

## The problem

Bitcoin's privacy/usability/compliance triangle is usually a pick-two:

- **Reusable address** (publish once) → but address reuse links every payment publicly.
- **Fresh address per payment** → unlinkable, but you must hand out a new address each
  time, and there's no clean way to give an auditor *read-only* visibility.
- **Compliance visibility** → usually means handing over spend-capable keys or trusting a
  custodian, conflating "can see" with "can move funds."

On Arkade specifically, the usual silent-payment trick (scan the public chain) doesn't
even apply: the offchain VTXO tx graph is **not publicly enumerable**.

## The product

One static, publishable address — `treasury@arkade.btc` — where:

1. **Senders** pay it repeatedly; each payment lands on a fresh, unlinkable pubkey.
2. **Third parties** can't link two payments to the same recipient.
3. A **delegated view key** lets a scanner/auditor detect *every* inbound payment — and
   **provably cannot spend any of it**. Detection and audit are the same capability.

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

## Who it's for

| User | Job to be done | What they hold |
|------|----------------|----------------|
| **Treasury / merchant** | Publish one address, receive unlinkable inbound, stay auditable | full keys (scan + spend) |
| **Compliance auditor** | See 100% of one entity's inbound, prove no spend authority | view key only (scan secret + spend pubkey) |
| **Operator / scanner** | Detect inbound for delegated recipients off the tx stream it already sees | view keys it's been delegated |
| **Sender** | Pay a reusable address without leaking a link to prior payments | nothing persistent |

## Why this shape (forced by Arkade)

- **No on-chain announcement / no relay.** The shared secret comes from the sender's
  spent-VTXO input key `A` and outpoint, already in the Arkade tx. Nothing extra is
  broadcast; the data to detect *and* spend is co-located with the payment.
- **Detection via a sidecar, not passive scanning.** Arkade's tx graph is auth-gated, so
  only a party that already sees the txs can scan. `StealthScanner` models that party; the
  recipient delegates its view key. That view key is exactly the auditor's key.
- **Operator unchanged.** `P` plugs into the standard VTXO script as `userPK`
  (`checkSig(userPK) && checkSig(operatorPK)`). The operator co-signs, none the wiser.

(Full reasoning and primitive comparison in `SURVEY.md`; structure in `ARCHITECTURE.md`.)

## Differentiators

- **Read/spend separation is structural, not policy.** The view key literally lacks the
  spend secret; "auditor can't spend" is enforced by the curve, not by a permission flag.
- **Detection == audit.** One primitive serves both the recipient's wallet and the
  compliance dashboard.
- **Zero protocol changes to Arkade.** No new message types, no extra broadcast, operator
  untouched.

## Scope (v0) and honesty notes

- **Single-input** silent payment (no multi-input aggregation). Keeps the input-hash
  tweak for replay protection.
- Unlinkable to third parties; the sidecar/auditor *can* link inbound (by design — it
  holds the scan key) but **cannot spend**.
- **Not** hidden: amounts, and the operator's privileged transaction-graph view.
- Meta-address is hex-encoded; swap for bech32m before any real use.

## Status

- ✅ Crypto, scan, spend-key, view key, resolver — proven end-to-end (`bun run test`, 13/13).
- 🔌 One live-verify item: implement `sidecar.ts::parseIndexerTx` against the Arkade
  indexer (`GetVirtualTxs` / `GetSubscription`). All other code runs against structured
  `ArkadeTx` today.

## Roadmap

1. Implement `parseIndexerTx`; drive the sidecar off a live regtest tx stream.
2. Wire `senderDerive` into an Arkade `sendBitcoin` that funds `VTXO(P)`.
3. Compliance dashboard over `StealthScanner.getHistory(label)`.
4. Multi-input aggregation; bech32m meta-address; amount confidentiality (research).
