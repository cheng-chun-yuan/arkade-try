# Survey — Reusable, unlinkable, auditable payments (and why Arkade forces this shape)

Goal restated: one **static** address a recipient can publish forever, where each
inbound payment is **unlinkable** to third parties, plus an **opt-in view key** that
lets a compliance auditor see *all* of one entity's inbound — but never spend.

## 1. The primitive landscape

| Approach | Reusable addr | Unlinkable on-chain | Detection model | View/audit key | Spend separated from view | Extra broadcast data |
|---|---|---|---|---|---|---|
| Plain BIP-32 address reuse | ✅ | ❌ (all links) | trivial | n/a | n/a | none |
| HD gap-limit (new addr/payment) | ❌ (must hand out new) | ✅ | wallet scans own addrs | ❌ | ❌ | none |
| **Stealth addresses (BIP-47)** | ✅ | ✅ | needs a **notification tx** | partial | ❌ | yes (notification) |
| **Silent payments (BIP-352)** | ✅ | ✅ | scan chain w/ scan key | ✅ scan key | ✅ scan vs spend | **none** |
| Monero-style (dual-key + view key) | ✅ | ✅ | scan w/ view key | ✅ view key | ✅ | none (own chain) |
| Lightning / BOLT12 offers | ✅ (offer) | ✅ (per-invoice) | interactive (onion msg) | ❌ | ❌ | interactive round-trip |

**Takeaway.** Two families separate *viewing* from *spending* with a static address and
no per-payment announcement: **BIP-352 silent payments** and **Monero's dual-key + view
key**. Monero needs its own chain; BIP-352 is the Bitcoin-native expression of the same
idea. So BIP-352 is the right primitive — but BIP-352 assumes a *publicly enumerable
UTXO set* to scan. Arkade does not have one. That mismatch is the whole design problem.

## 2. What Arkade changes

Arkade is a shared-UTXO / VTXO system: payments are **offchain virtual TXOs** co-signed
by an operator. Relevant facts:

- A VTXO spend reveals the spender's input pubkey **`A`** in the witness, and the spent
  **outpoint** is part of the tx. → the ingredients for an ECDH shared secret are already
  in every transaction. **No extra broadcast is needed** (unlike BIP-47 notification txs).
- The VTXO script is `checkSig(userPK) && checkSig(operatorPK)`. A stealth-derived
  pubkey `P` plugs straight in as `userPK`; the operator co-signs without knowing `P` is
  special. → **operator unchanged.**
- The offchain tx graph is **not public**: `GetVirtualTxs` is auth-gated. → a recipient
  *cannot* scan the way a BIP-352 wallet scans the chain. Only a party that already sees
  the txs (the operator, or a delegate streamed from it) can detect inbound.

These three facts force a specific shape (next section). This isn't a design preference;
it's what the substrate allows.

## 3. Design consequences (forced, not chosen)

1. **Secret source = the spend itself.** Derive the shared secret from `A` + outpoint,
   already in the tx. Nothing extra is broadcast, and everything needed to detect *and*
   spend a payment is co-located with the payment (and recoverable from a seed).
2. **Detection = a sidecar, not passive scanning.** Model the only party who can see the
   txs as a `StealthScanner` holding a delegated **view key**. The recipient delegates
   detection. This is not a workaround — it is the honest model of who can observe an
   Arkade tx graph.
3. **View key == audit key.** The scan secret that enables detection is exactly the
   capability a compliance auditor wants: full inbound visibility, zero spend authority.
   Detection and audit collapse into one primitive — a feature, not a coincidence.

## 4. Cryptographic core (BIP-352, single-input v0)

```
input_hash = H(outpoint ‖ A)                         # binds secret to the spent VTXO (replay protection)
ecdh       = input_hash · a · B_scan                 # sender   (a = spender secret)
           = input_hash · b_scan · A                 # recipient/scanner (equal: a·B_scan == b_scan·A)
k_t        = H(ecdh ‖ t)                              # per-output tweak, t = output index
P          = B_spend + k_t · G                        # funded pubkey  (sender & scanner can compute)
p          = b_spend + k_t   (mod n)                  # spend secret   (recipient only; needs b_spend)
```

- **Scanner** holds `b_scan` + `B_spend` (public) → computes `P` to detect. Lacks
  `b_spend` → cannot compute `p`. **Detect-only is structural, not policy.**
- **Unlinkability**: different `(outpoint, A, t)` → different `ecdh` → different `P`. Two
  payments to the same meta-address share no visible link to a third party.

## 5. Honest scope of v0

- **Single-input** silent payment (no multi-input key aggregation). Keeps the input-hash
  tweak for replay protection.
- Unlinkable to third parties; the sidecar/auditor *can* link inbound **by design** (it
  holds the scan key) but **cannot spend**.
- **Not hidden**: amounts, and the operator's privileged tx-graph view. Future work.
- Meta-address hex-encoded for the hackathon; swap for **bech32m** before real use.
- **One live-verify item**: confirm the Arkade indexer exposes per-input `userPK` and
  per-output `(pubkey, outpoint, amount)`, then implement `sidecar.ts::parseIndexerTx`.

## 6. Prior art referenced

- **BIP-352** Silent Payments — the scan/spend split and input-hash tweak.
- **BIP-47** Payment Codes — the reusable-address idea, but needs a notification tx
  (which Arkade lets us avoid).
- **BIP-353** DNS payment instructions — shape for `name@domain` → payment data resolution.
- **Monero** dual-key stealth + view keys — the detection/audit-key equivalence.
- **Arkade / ark** VTXO model — `checkSig(userPK) && checkSig(operatorPK)`, auth-gated
  `GetVirtualTxs`, witness-revealed input pubkeys.
