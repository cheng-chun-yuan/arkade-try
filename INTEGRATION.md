# Integrating Arkade silent payments into your app

This guide shows how another app wires in Arkade Stealth. Pick the **tier** that
matches what your app does. All three share one scan core — no forked crypto — and the
view key is **detect-only everywhere**: spending always needs `b_spend`, which a `ViewKey`
structurally never carries.

| Tier | You are… | You ship | View key lives | Effort |
|------|----------|----------|----------------|--------|
| **0 — Sender** | a wallet/PSP that **pays** a stealth address | `stealth.ts` + `resolver.ts` | nowhere (you hold none) | `resolve → derive → fund` |
| **1 — Detector** | a wallet/exchange/auditor that **sees** inbound | `treewalk.ts` (+ your indexer adapter) | in your process | implement `fetchBatches` |
| **2 — Hosted** | a service wanting **zero infra** | call a hosted scan API | leaves you → reaches host | one POST + a webhook |

Toolchain is **Bun**. Import paths are extensionless (`from './stealth'`).

---

## Tier 0 — Send to a stealth address

Resolve the recipient's static meta-address, derive a one-time pubkey `P`, and fund a
VTXO whose `userPK` is `P`. You never touch a view key or scan anything.

```ts
import { StaticResolver } from './resolver';
import { senderDeriveMulti, decodeMetaAddress } from './stealth';

// 1. Resolve name@domain → meta-address (swap StaticResolver for a DNSSEC TXT lookup live)
const resolver = new StaticResolver();
const meta = resolver.resolve('treasury@arkade.btc');
// ...or decode a meta-address string the user pasted:
// const meta = decodeMetaAddress(hexString);

// 2. Derive P from the VTXOs you are spending.
//    spenderPrivs  = the input secrets you control (one or many)
//    inputVtxoIds  = the canonical id of each spent VTXO (the replay nonce)
//    t             = the output's leaf index inside the funding vtx
const { P } = senderDeriveMulti({
  meta,
  spenderPrivs: [myVtxoSecret],
  inputVtxoIds: ['vtxo:txid:0'],
  t: 0,
});

// 3. Fund a VTXO with userPK = P via your normal Arkade sendBitcoin.
//    The operator co-signs P as an ordinary userPK — nothing about it looks special.
await arkade.sendBitcoin({ userPK: P, amountSats: 50_000 });
```

That's the whole sender integration. Paying the same meta-address again with a different
input or `t` yields an unlinkable `P`.

---

## Tier 1 — Detect inbound in your own process

Your app pulls the batch tree from the Arkade indexer and scans locally with the
recipient's view key. The view key never leaves your process. You implement **one**
interface — the transport — and get scanning, history, cursor, and refresh-dedup free.

```ts
import { TreeScanner, type IndexerAdapter, type FetchResult } from './treewalk';
import { viewKeyOf, generateRecipient } from './stealth';

// 1. Implement the one integration point: map your indexer → RawBatchTree[].
//    `parseTree` (inside treewalk.ts) is where live GetVirtualTxs / tree responses
//    get mapped into the StealthVtx schema. Return new trees since `cursor`.
const adapter: IndexerAdapter = {
  async fetchBatches(cursor: string | null): Promise<FetchResult> {
    const { batches, next } = await myIndexer.getBatchesSince(cursor);
    return {
      trees: batches.map(toRawBatchTree), // your mapping to { batchId, txs:[{vtxId, inputs, outputs}] }
      nextCursor: next, // null when caught up
    };
  },
};

// 2. Register a view key (here from a generated recipient; in practice the user's).
const recipient = generateRecipient();
const scanner = new TreeScanner(adapter);
scanner.registerViewKey('user-42', viewKeyOf(recipient), (payment) => {
  console.log('inbound', payment.P, payment.amount, 'in batch', payment.batchId);
});

// 3a. Steady state — pull only new batches and scan them. Cheap, idempotent.
await scanner.sync();

// 3b. Recovery / fresh device — replay everything from genesis.
//     Reproduces the exact same history from seed + indexer alone.
await scanner.rescan();

const history = scanner.getHistory('user-42'); // backs a dashboard / balance view
```

**Spending what you detect.** The detector cannot spend. The wallet holding `b_spend`
turns a detected payment into a spend key:

```ts
import { recipientSpendKeyMulti } from './stealth';

const { senderPubs, inputVtxoIds, t } = payment.derivation;
const { priv, pub } = recipientSpendKeyMulti({
  scanPriv: recipient.scan.priv,
  spendPriv: recipient.spend.priv, // only the wallet has this — never the detector
  senderPubs, inputVtxoIds, t,
});
// pub === payment.P, and `priv` signs the VTXO spend.
```

**Refresh is handled for you.** When a recipient renews a received VTXO (Arkade VTXOs
expire), the same `P` reappears in a later batch. `TreeScanner` treats it as a renewal —
updates the payment's `batchId`, emits no duplicate inbound.

---

## Tier 2 — Use a hosted scanner (zero infra)

If you don't want to run a scanner, POST a view key to a hosted service and receive a
webhook per detected payment. Lightest effort; the trade is that the view key leaves your
process. It still **cannot spend** — even a fully compromised host only gains visibility.

```ts
// Your side: register, then receive webhooks.
await fetch('https://scan.example/register', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({
    label: 'user-42',
    viewKey: { bScan: viewKey.bScan.toString(), bSpendPub: viewKey.bSpendPub },
    webhookUrl: 'https://yourapp.example/arkade/inbound',
  }),
});

// Your webhook endpoint receives an IncomingPayment per detection:
// { label, batchId, vtxId, P, amount, leafIndex, derivation }
```

The host is just Tier 1 wrapped in a service. The transport-agnostic core is
`HostedScanner` in `hosted.ts`; bind it to Bun.serve / Express to expose `/register` and
a polling loop:

```ts
import { HostedScanner } from './hosted';

const host = new HostedScanner(adapter, async (url, payment) => {
  await fetch(url, { method: 'POST', body: JSON.stringify(payment) });
});
host.register(req.body);          // on POST /register
setInterval(() => host.poll(), 5_000); // pull new batches, fan out webhooks
```

---

## The one thing to verify against a live node

Everything above runs on the structured `StealthVtx` schema. The **only** place that
touches the live Arkade format is `parseTree` in `treewalk.ts`. To go live, confirm your
indexer exposes, per batch-tree node:

- per input — the spender's `userPK` (`A`) and the canonical `vtxoId` of the spent VTXO,
- per output — the leaf `userPK` (`P`), `amount`, and leaf index.

Map those into `RawBatchTree` inside your adapter, and the rest of the pipeline is
unchanged. See `demo.test.ts` for a runnable end-to-end example of all three tiers.
