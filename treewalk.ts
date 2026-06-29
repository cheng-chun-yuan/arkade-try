/**
 * treewalk.ts — client-side batch-tree scanning (Tier 1).
 *
 * Arkade is off-chain: there is no public UTXO set to scan. Instead the
 * recipient's own client PULLS the batch/round tree from the auth-gated indexer
 * and scans it LOCALLY with a view key. The view key never leaves the device.
 *
 * This file owns the single Arkade-format seam, client-side: `parseTree`
 * normalizes a raw batch tree into `StealthVtx[]` (the relocated
 * `sidecar.ts::parseIndexerTx`). Everything downstream runs on the structured
 * `StealthVtx` schema and the multi-input BIP-352 core in `stealth.ts`.
 *
 * The scanner DETECTS every inbound payment to a registered view key and can
 * NEVER spend — it holds no `b_spend`.
 */

import {
  type ViewKey,
  scanMatchesMulti,
} from './stealth';

// ----------------------------------------------------------------------------
// schema — the "stealth-scannable virtual tx" (what the indexer must surface)
// ----------------------------------------------------------------------------

/**
 * One virtual-tx node of a batch tree, surfaced for view-key scanning.
 * BIP-352's four commitments, off-chain:
 *   - inputs[].userPK  = Aᵢ            (revealed when a VTXO is spent)
 *   - inputs[].vtxoId  = replay nonce  (canonical id of the spent VTXO)
 *   - outputs[].userPK = P             (the funded leaf VTXO pubkey)
 *   - outputs[].leafIndex = t          (the BIP-352 output counter)
 */
export interface StealthVtx {
  batchId: string;
  vtxId: string;
  inputs: Array<{ userPK: string; vtxoId: string }>;
  outputs: Array<{ userPK: string; amount: number; leafIndex: number }>;
}

/** A raw batch tree as the indexer exposes it (shape wired in `parseTree`). */
export interface RawBatchTree {
  batchId: string;
  txs: Array<{
    vtxId: string;
    inputs: Array<{ userPK: string; vtxoId: string }>;
    outputs: Array<{ userPK: string; amount: number; leafIndex: number }>;
  }>;
}

/**
 * THE LIVE-VERIFY SEAM. Walk a raw batch tree → flat `StealthVtx[]`.
 *
 * Confirm the Arkade indexer exposes, per tree node: each input's spender
 * `userPK` + the canonical `vtxoId` of the spent VTXO, and each output's leaf
 * `userPK` (= P) + amount + position. Those are all the scan core needs. The
 * modeled `RawBatchTree` already matches that contract; wiring a live node means
 * mapping its `GetVirtualTxs` / tree response into this shape here and nowhere
 * else.
 */
export function parseTree(raw: RawBatchTree): StealthVtx[] {
  return raw.txs.map((tx) => ({
    batchId: raw.batchId,
    vtxId: tx.vtxId,
    inputs: tx.inputs,
    outputs: tx.outputs,
  }));
}

// ----------------------------------------------------------------------------
// indexer transport (pluggable — the Tier-1 integration point)
// ----------------------------------------------------------------------------

export interface FetchResult {
  trees: RawBatchTree[];
  /** Cursor to pass next time. `null` ⇒ caller is fully caught up. */
  nextCursor: string | null;
}

/**
 * The one interface an integrator implements to plug their indexer transport in.
 * Given the last cursor (`null` = from genesis), return new batch trees and the
 * advanced cursor. Everything else — scanning, history, refresh dedup — is free.
 */
export interface IndexerAdapter {
  fetchBatches(cursor: string | null): Promise<FetchResult>;
}

// ----------------------------------------------------------------------------
// detected payments
// ----------------------------------------------------------------------------

export interface IncomingPayment {
  label: string;
  batchId: string;
  vtxId: string;
  P: string;
  amount: number;
  leafIndex: number;
  /** What a recipient needs to derive the spend key (multi-input). */
  derivation: { senderPubs: string[]; inputVtxoIds: string[]; t: number };
}

type IncomingHandler = (p: IncomingPayment) => void;

interface Registration {
  viewKey: ViewKey;
  onIncoming?: IncomingHandler;
}

// ----------------------------------------------------------------------------
// TreeScanner — pull, scan, dedup refreshes, track a cursor
// ----------------------------------------------------------------------------

export class TreeScanner {
  private regs = new Map<string, Registration>();
  private history = new Map<string, IncomingPayment[]>();
  /** Detected P's per label — drives idempotent refresh/self-spend dedup. */
  private knownP = new Map<string, Set<string>>();
  private cursor: string | null = null;

  constructor(private readonly adapter: IndexerAdapter) {}

  /** Register a recipient's view key under a label. Detect-only. */
  registerViewKey(label: string, viewKey: ViewKey, onIncoming?: IncomingHandler): void {
    this.regs.set(label, { viewKey, onIncoming });
    if (!this.history.has(label)) this.history.set(label, []);
    if (!this.knownP.has(label)) this.knownP.set(label, new Set());
  }

  /** Current scan cursor (last batch consumed). */
  getCursor(): string | null {
    return this.cursor;
  }

  /**
   * Scan one virtual tx against every registered view key. Aggregates inputs
   * (BIP-352) and tests each output with `t = leafIndex`. Handles refreshes:
   * an output P already seen is a renewal (update batchId, no new inbound).
   */
  scanVtx(vtx: StealthVtx): IncomingPayment[] {
    const detected: IncomingPayment[] = [];
    if (vtx.inputs.length === 0) return detected;

    const senderPubs = vtx.inputs.map((i) => i.userPK);
    const inputVtxoIds = vtx.inputs.map((i) => i.vtxoId);

    for (const [label, reg] of this.regs) {
      const known = this.knownP.get(label)!;
      for (const out of vtx.outputs) {
        // Renewal: a known P re-anchored into a new batch — not a new payment.
        if (known.has(out.userPK)) {
          const prior = this.history.get(label)!.find((p) => p.P === out.userPK);
          if (prior) prior.batchId = vtx.batchId;
          continue;
        }
        const params = { viewKey: reg.viewKey, senderPubs, inputVtxoIds, t: out.leafIndex };
        if (!scanMatchesMulti(params, out.userPK)) continue;

        const payment: IncomingPayment = {
          label,
          batchId: vtx.batchId,
          vtxId: vtx.vtxId,
          P: out.userPK,
          amount: out.amount,
          leafIndex: out.leafIndex,
          derivation: { senderPubs, inputVtxoIds, t: out.leafIndex },
        };
        known.add(out.userPK);
        this.history.get(label)!.push(payment);
        reg.onIncoming?.(payment);
        detected.push(payment);
      }
    }
    return detected;
  }

  /**
   * Incremental pull: fetch batches after the stored cursor, scan them, and
   * advance the cursor. Fails closed — on a thrown fetch the cursor is left
   * untouched so the next sync retries the same gap.
   */
  async sync(): Promise<IncomingPayment[]> {
    const { trees, nextCursor } = await this.adapter.fetchBatches(this.cursor);
    const detected: IncomingPayment[] = [];
    for (const tree of trees) {
      for (const vtx of parseTree(tree)) detected.push(...this.scanVtx(vtx));
    }
    this.cursor = nextCursor;
    return detected;
  }

  /**
   * Full rescan from genesis (seed recovery / fresh device). Clears state and
   * replays the whole stream. `sync()` accumulation must equal `rescan()`.
   */
  async rescan(): Promise<Map<string, IncomingPayment[]>> {
    for (const label of this.regs.keys()) {
      this.history.set(label, []);
      this.knownP.set(label, new Set());
    }
    this.cursor = null;
    // Drain the adapter from genesis until it reports caught up.
    let cursor: string | null = null;
    do {
      const { trees, nextCursor } = await this.adapter.fetchBatches(cursor);
      for (const tree of trees) {
        for (const vtx of parseTree(tree)) this.scanVtx(vtx);
      }
      cursor = nextCursor;
      this.cursor = nextCursor;
    } while (cursor !== null);

    const out = new Map<string, IncomingPayment[]>();
    for (const label of this.regs.keys()) out.set(label, this.getHistory(label));
    return out;
  }

  /** Inbound history for a label — backs a compliance dashboard. */
  getHistory(label: string): IncomingPayment[] {
    return [...(this.history.get(label) ?? [])];
  }
}
