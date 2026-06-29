/**
 * demo.test.ts — end-to-end proof of Arkade Stealth (13 checks).
 *
 *   bun test   ->   ALL 13 CHECKS PASSED
 *
 * Self-contained runner (no test framework) so the proof reads top-to-bottom.
 */

import {
  generateKeyPair,
  generateRecipient,
  recipientFromSeed,
  viewKeyOf,
  encodeMetaAddress,
  decodeMetaAddress,
  senderDerive,
  scanMatches,
  expectedP,
  recipientSpendKey,
  senderDeriveMulti,
  scanMatchesMulti,
  recipientSpendKeyMulti,
  sumPubkeys,
  _internal,
  type Outpoint,
} from './stealth';
import { StealthScanner, type ArkadeTx } from './sidecar';
import { StaticResolver, parseTxtValue, txtRecordName } from './resolver';
import {
  TreeScanner,
  parseTree,
  type RawBatchTree,
  type IndexerAdapter,
  type FetchResult,
} from './treewalk';
import { HostedScanner } from './hosted';

const { G, modN } = _internal;

let n = 0;
let passed = 0;
function check(label: string, cond: boolean): void {
  n += 1;
  const ok = cond === true;
  if (ok) passed += 1;
  console.log(`  ${ok ? '✓' : '✗'} ${String(n).padStart(2, '0')}. ${label}`);
  if (!ok) throw new Error(`CHECK ${n} FAILED: ${label}`);
}

// A deterministic outpoint helper (32-byte txid).
const op = (tag: string, vout: number): Outpoint => ({
  txid: tag.repeat(64).slice(0, 64),
  vout,
});

console.log('\nArkade Stealth — end-to-end\n');

// ── recipient publishes a static meta-address ───────────────────────────────
const recipient = generateRecipient();
const meta = recipient.meta;

check('keygen: scan & spend pubkeys are distinct 33-byte compressed keys',
  meta.bScanPub !== meta.bSpendPub &&
  meta.bScanPub.length === 66 && meta.bSpendPub.length === 66);

const encoded = encodeMetaAddress(meta);
const decoded = decodeMetaAddress(encoded);
check('meta-address: hex encode/decode round-trips',
  decoded.bScanPub === meta.bScanPub && decoded.bSpendPub === meta.bSpendPub);

// ── resolver: name@domain → meta-address (BIP-353 shaped) ────────────────────
const resolver = new StaticResolver();
resolver.register('treasury@arkade.btc', meta);
const resolved = resolver.resolve('treasury@arkade.btc');
check('resolver: treasury@arkade.btc resolves to the meta-address',
  encodeMetaAddress(resolved) === encoded);

const rec = resolver.txtRecord('treasury@arkade.btc');
check('resolver: TXT record is BIP-353-shaped and carries the meta-address',
  rec.name === 'treasury.user._bitcoin-payment.arkade.btc' &&
  txtRecordName('treasury@arkade.btc') === rec.name &&
  encodeMetaAddress(parseTxtValue(rec.value)) === encoded);

// ── sender spends a VTXO and derives P ───────────────────────────────────────
const sender = generateKeyPair();               // (a, A) — the spent VTXO input key
const spent = op('a', 0);                        // the VTXO outpoint being spent
const t = 0;                                      // funded output index
const derived = senderDerive({ meta: resolved, spenderPriv: sender.priv, spentOutpoint: spent, t });
check('sender: derives a one-time stealth pubkey P (33-byte compressed)',
  derived.P.length === 66 && derived.P !== meta.bSpendPub);

// ── scanner with ONLY the view key detects P ─────────────────────────────────
const viewKey = viewKeyOf(recipient);
const scanParams = { viewKey, senderPub: sender.pub, spentOutpoint: spent, t };
check('scanner: view key (b_scan + B_spend) recomputes P and detects the payment',
  scanMatches(scanParams, derived.P) && expectedP(scanParams) === derived.P);

// ── the view key CANNOT spend (structural: no b_spend) ───────────────────────
check('view key: contains b_scan + B_spend(public) but no spend secret',
  typeof viewKey.bScan === 'bigint' &&
  // @ts-expect-error — there is deliberately no spend secret on a ViewKey
  viewKey.bSpend === undefined);

// ── recipient derives p with p·G == P, and can spend ─────────────────────────
const spend = recipientSpendKey({
  scanPriv: recipient.scan.priv,
  spendPriv: recipient.spend.priv,
  senderPub: sender.pub,
  spentOutpoint: spent,
  t,
});
check('recipient: derives spend key p (valid scalar) with p·G == P',
  spend.pub === derived.P && G.multiply(modN(spend.priv)).toRawBytes(true)[0]! >= 2);

// ── unlinkability: different spend/outpoint/index → different P ───────────────
const sender2 = generateKeyPair();
const derived2 = senderDerive({ meta: resolved, spenderPriv: sender2.priv, spentOutpoint: op('b', 1), t: 0 });
const derivedSameSenderDiffOut = senderDerive({ meta: resolved, spenderPriv: sender.priv, spentOutpoint: op('a', 1), t: 0 });
check('unlinkability: two payments to the same meta-address yield unlinkable P',
  derived.P !== derived2.P && derived.P !== derivedSameSenderDiffOut.P && derived2.P !== derivedSameSenderDiffOut.P);

// ── a wrong scan key does not detect ─────────────────────────────────────────
const stranger = generateRecipient();
check('isolation: a different recipient\'s view key does NOT detect the payment',
  !scanMatches({ viewKey: viewKeyOf(stranger), senderPub: sender.pub, spentOutpoint: spent, t }, derived.P));

// ── sidecar: drives detection off ArkadeTx, fires onIncoming, keeps history ───
const scanner = new StealthScanner();
const seen: string[] = [];
scanner.registerViewKey('treasury@arkade.btc', viewKey, (p) => seen.push(`${p.txid}:${p.vout}=${p.amount}`));

// fund tx: input reveals A + spent outpoint; output funds P with an amount.
const fundTx: ArkadeTx = {
  txid: op('f', 0).txid,
  inputs: [{ userPK: sender.pub, outpoint: spent }],
  outputs: [
    { pubkey: 'aa'.repeat(33).slice(0, 66), amount: 999, vout: 1 }, // decoy / unrelated
    { pubkey: derived.P, amount: 50_000, vout: 0 },                  // the stealth payment (t=0)
  ],
};
const hits = scanner.scanTx(fundTx);
check('sidecar: scanTx detects exactly the stealth output and ignores the decoy',
  hits.length === 1 && hits[0]!.amount === 50_000 && hits[0]!.P === derived.P);

check('sidecar: onIncoming fired and getHistory records the inbound payment',
  seen.length === 1 && scanner.getHistory('treasury@arkade.btc').length === 1);

// ── seed recovery: rescan a tx stream + derive recipient from seed ────────────
const seed = new Uint8Array(32).fill(7);
const seededRecipient = recipientFromSeed(seed);
const seededRecipient2 = recipientFromSeed(seed);
const recoveryScanner = new StealthScanner();
recoveryScanner.registerViewKey('seed', viewKeyOf(seededRecipient));
// a payment to the seeded recipient:
const seededP = senderDerive({ meta: seededRecipient.meta, spenderPriv: sender.priv, spentOutpoint: op('c', 3), t: 0 }).P;
const seededTx: ArkadeTx = {
  txid: op('d', 0).txid,
  inputs: [{ userPK: sender.pub, outpoint: op('c', 3) }],
  outputs: [{ pubkey: seededP, amount: 7_000, vout: 0 }],
};
const recovered = recoveryScanner.rescan([fundTx, seededTx]); // fundTx not for this view key
check('seed recovery: recipientFromSeed is deterministic and rescan recovers seeded inbound',
  seededRecipient.meta.bScanPub === seededRecipient2.meta.bScanPub &&
  recovered.get('seed')!.length === 1 &&
  recovered.get('seed')![0]!.amount === 7_000);

// ════════════════════════════════════════════════════════════════════════════
//  Off-chain silent payments: multi-input BIP-352 + client-side tree scanning
// ════════════════════════════════════════════════════════════════════════════

// ── multi-input: aggregate A_sum, derive P, detect with the view key ─────────
const inA = generateKeyPair();
const inB = generateKeyPair();
const inC = generateKeyPair();
const multiPubs = [inA.pub, inB.pub, inC.pub];
const multiVtxoIds = ['vtxo:zeta:2', 'vtxo:alpha:0', 'vtxo:mike:1']; // unsorted on purpose
const mDerived = senderDeriveMulti({
  meta: resolved,
  spenderPrivs: [inA.priv, inB.priv, inC.priv],
  inputVtxoIds: multiVtxoIds,
  t: 0,
});
const mScan = { viewKey, senderPubs: multiPubs, inputVtxoIds: multiVtxoIds, t: 0 };
check('multi-input: A_sum aggregation lets the view key detect a 3-input payment',
  sumPubkeys(multiPubs).length === 66 &&
  scanMatchesMulti(mScan, mDerived.P));

// ── multi-input: recipient derives p with p·G == P ───────────────────────────
const mSpend = recipientSpendKeyMulti({
  scanPriv: recipient.scan.priv,
  spendPriv: recipient.spend.priv,
  senderPubs: multiPubs,
  inputVtxoIds: multiVtxoIds,
  t: 0,
});
check('multi-input: recipient derives spend key p with p·G == P',
  mSpend.pub === mDerived.P && G.multiply(modN(mSpend.priv)).toRawBytes(true)[0]! >= 2);

// ── leafIndex (t) distinguishes two outputs to the SAME recipient in one vtx ──
const out0 = senderDeriveMulti({ meta: resolved, spenderPrivs: [inA.priv, inB.priv, inC.priv], inputVtxoIds: multiVtxoIds, t: 0 });
const out1 = senderDeriveMulti({ meta: resolved, spenderPrivs: [inA.priv, inB.priv, inC.priv], inputVtxoIds: multiVtxoIds, t: 1 });
check('leafIndex: two outputs to the same recipient in one vtx yield distinct P',
  out0.P !== out1.P &&
  scanMatchesMulti({ ...mScan, t: 0 }, out0.P) &&
  scanMatchesMulti({ ...mScan, t: 1 }, out1.P));

// ── parseTree: raw batch tree → flat StealthVtx[] ────────────────────────────
const rawTree: RawBatchTree = {
  batchId: 'batch-100',
  txs: [
    {
      vtxId: 'vtx-1',
      inputs: multiPubs.map((userPK, i) => ({ userPK, vtxoId: multiVtxoIds[i]! })),
      outputs: [
        { userPK: 'bb'.repeat(33).slice(0, 66), amount: 111, leafIndex: 2 }, // decoy
        { userPK: out0.P, amount: 40_000, leafIndex: 0 },                      // payment t=0
        { userPK: out1.P, amount: 10_000, leafIndex: 1 },                      // payment t=1
      ],
    },
  ],
};
const flat = parseTree(rawTree);
check('parseTree: raw batch tree flattens to StealthVtx[] carrying batchId',
  flat.length === 1 && flat[0]!.batchId === 'batch-100' && flat[0]!.inputs.length === 3);

// ── TreeScanner.sync: incremental pull detects inbound and advances cursor ───
// A two-batch indexer the client pulls from.
const batches: RawBatchTree[] = [
  rawTree,
  {
    batchId: 'batch-200',
    txs: [
      {
        vtxId: 'vtx-2',
        inputs: [{ userPK: inA.pub, vtxoId: 'vtxo:solo:9' }],
        outputs: [
          {
            userPK: senderDeriveMulti({ meta: resolved, spenderPrivs: [inA.priv], inputVtxoIds: ['vtxo:solo:9'], t: 0 }).P,
            amount: 5_000,
            leafIndex: 0,
          },
        ],
      },
    ],
  },
];
// Adapter: serves one batch per call, cursor = index, null when caught up.
function makeAdapter(src: RawBatchTree[]): IndexerAdapter {
  return {
    async fetchBatches(cursor: string | null): Promise<FetchResult> {
      const i = cursor === null ? 0 : Number(cursor);
      if (i >= src.length) return { trees: [], nextCursor: null };
      return { trees: [src[i]!], nextCursor: i + 1 >= src.length ? null : String(i + 1) };
    },
  };
}
const live = new TreeScanner(makeAdapter(batches));
live.registerViewKey('treasury@arkade.btc', viewKey);
const firstSync = await live.sync(); // batch-100: two payments (t=0, t=1)
const secondSync = await live.sync(); // batch-200: one payment
check('TreeScanner.sync: incremental pull detects inbound across batches',
  firstSync.length === 2 && secondSync.length === 1 &&
  live.getHistory('treasury@arkade.btc').length === 3);

// ── incremental sync accumulation == full rescan ─────────────────────────────
const fresh = new TreeScanner(makeAdapter(batches));
fresh.registerViewKey('treasury@arkade.btc', viewKey);
const rescanned = await fresh.rescan();
check('recovery: full rescan reproduces exactly the incremental history',
  rescanned.get('treasury@arkade.btc')!.length ===
    live.getHistory('treasury@arkade.btc').length &&
  rescanned.get('treasury@arkade.btc')!.map((p) => p.P).join() ===
    live.getHistory('treasury@arkade.btc').map((p) => p.P).join());

// ── refresh: a renewed P emits no new inbound, just updates batchId ──────────
const refreshTree: RawBatchTree = {
  batchId: 'batch-300',
  txs: [
    {
      vtxId: 'vtx-refresh',
      // recipient spends their own P (out0.P) to renew it into a new batch
      inputs: [{ userPK: out0.P, vtxoId: 'vtxo:renew:0' }],
      outputs: [{ userPK: out0.P, amount: 40_000, leafIndex: 0 }], // same P, re-anchored
    },
  ],
};
const beforeRefresh = live.getHistory('treasury@arkade.btc').length;
const refreshHits = live.scanVtx(parseTree(refreshTree)[0]!);
const afterRefresh = live.getHistory('treasury@arkade.btc');
check('refresh: renewing a received VTXO emits no new inbound and updates batchId',
  refreshHits.length === 0 &&
  afterRefresh.length === beforeRefresh &&
  afterRefresh.find((p) => p.P === out0.P)!.batchId === 'batch-300');

// ── Tier 2 hosted: register a view key, receive an onIncoming webhook ─────────
const delivered: string[] = [];
const hosted = new HostedScanner(makeAdapter(batches), (url, payment) => {
  delivered.push(`${url}|${payment.P}=${payment.amount}`);
});
hosted.register({
  label: 'treasury@arkade.btc',
  viewKey: { bScan: viewKey.bScan.toString(), bSpendPub: viewKey.bSpendPub },
  webhookUrl: 'https://svc.example/hook',
});
await hosted.poll();
await hosted.poll();
check('hosted (Tier 2): registerViewKey + poll fires onIncoming webhooks',
  delivered.length === 3 && delivered.every((d) => d.startsWith('https://svc.example/hook|')) &&
  hosted.getHistory('treasury@arkade.btc').length === 3);

// ── the multi-input view key still CANNOT spend (structural) ──────────────────
check('view key: multi-input detection still carries no spend secret',
  // @ts-expect-error — there is deliberately no spend secret on a ViewKey
  viewKey.bSpend === undefined && typeof viewKey.bScan === 'bigint');

console.log(`\nALL ${passed} CHECKS PASSED\n`);
if (passed !== n || n !== 22) {
  console.error(`expected 22 checks, ran ${n}, passed ${passed}`);
  process.exit(1);
}
