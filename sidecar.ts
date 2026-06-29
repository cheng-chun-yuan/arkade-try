/**
 * sidecar.ts — StealthScanner.
 *
 * Arkade's offchain tx graph is not publicly enumerable (`GetVirtualTxs` is
 * auth-gated), so silent-payment detection cannot be done by passive on-chain
 * scanning. Instead a party that already sees the txs (the operator, or a
 * delegate it streams to) runs this scanner. The recipient delegates its VIEW
 * KEY (scan secret + spend *public* key) to the scanner. That same view key is
 * what a compliance auditor uses — detection and audit are one primitive.
 *
 * The scanner can DETECT every inbound payment to a registered view key. It can
 * NEVER spend: it has no `b_spend` secret.
 */

import {
  type ViewKey,
  type Outpoint,
  scanMatches,
} from './stealth';

/** A normalized Arkade transaction (what `parseIndexerTx` must produce). */
export interface ArkadeTx {
  txid: string;
  inputs: Array<{
    /** The spender's input pubkey `A`, revealed in the spend witness. */
    userPK: string; // compressed hex
    outpoint: Outpoint;
  }>;
  outputs: Array<{
    /** The funded taproot/userPK pubkey `P`. */
    pubkey: string; // compressed hex
    amount: number; // sats
    vout: number;
  }>;
}

export interface IncomingPayment {
  label: string;
  txid: string;
  P: string;
  amount: number;
  vout: number;
  /** The (A, outpoint, t) a recipient needs to derive the spend key. */
  derivation: { senderPub: string; spentOutpoint: Outpoint; t: number };
}

type IncomingHandler = (p: IncomingPayment) => void;

interface Registration {
  viewKey: ViewKey;
  onIncoming?: IncomingHandler;
}

export class StealthScanner {
  private regs = new Map<string, Registration>();
  private history = new Map<string, IncomingPayment[]>();

  /**
   * Register a recipient's view key under a label (e.g. "treasury@arkade.btc").
   * The scanner now detects all inbound to this recipient — and only detects.
   */
  registerViewKey(label: string, viewKey: ViewKey, onIncoming?: IncomingHandler): void {
    this.regs.set(label, { viewKey, onIncoming });
    if (!this.history.has(label)) this.history.set(label, []);
  }

  /**
   * Scan one Arkade tx against every registered view key. For each output we
   * try to match it as a silent payment derived from input[0] (single-input v0).
   * Returns the payments detected in this tx.
   */
  scanTx(tx: ArkadeTx): IncomingPayment[] {
    const detected: IncomingPayment[] = [];
    const input = tx.inputs[0];
    if (!input) return detected;

    for (const [label, reg] of this.regs) {
      for (const out of tx.outputs) {
        const params = {
          viewKey: reg.viewKey,
          senderPub: input.userPK,
          spentOutpoint: input.outpoint,
          t: out.vout,
        };
        if (!scanMatches(params, out.pubkey)) continue;

        const payment: IncomingPayment = {
          label,
          txid: tx.txid,
          P: out.pubkey,
          amount: out.amount,
          vout: out.vout,
          derivation: { senderPub: input.userPK, spentOutpoint: input.outpoint, t: out.vout },
        };
        detected.push(payment);
        this.history.get(label)!.push(payment);
        reg.onIncoming?.(payment);
      }
    }
    return detected;
  }

  /** Inbound history for a label — the data backing a compliance dashboard. */
  getHistory(label: string): IncomingPayment[] {
    return [...(this.history.get(label) ?? [])];
  }

  /**
   * Replay a full tx stream from scratch (seed recovery / fresh auditor onboarding).
   * Clears prior detections for registered labels, then re-scans every tx.
   */
  rescan(txs: ArkadeTx[]): Map<string, IncomingPayment[]> {
    for (const label of this.regs.keys()) this.history.set(label, []);
    for (const tx of txs) this.scanTx(tx);
    const out = new Map<string, IncomingPayment[]>();
    for (const label of this.regs.keys()) out.set(label, this.getHistory(label));
    return out;
  }

  /**
   * LIVE-VERIFY ITEM. Normalize a raw indexer tx (`GetVirtualTxs` hex /
   * `GetSubscription` event) into an `ArkadeTx`.
   *
   * To implement, confirm the Arkade indexer exposes, per input, the spender's
   * `userPK` (revealed in the spend witness), and per output the taproot pubkey
   * + outpoint + amount. Those fields are all this scanner needs. Until then,
   * the scanner runs against structured `ArkadeTx` objects (proven in tests)
   * or the operator's own tx store in regtest.
   */
  parseIndexerTx(_raw: unknown): ArkadeTx {
    throw new Error(
      'parseIndexerTx: implement against live Arkade indexer format ' +
        '(GetVirtualTxs hex / GetSubscription events). See sidecar.ts header.',
    );
  }
}
