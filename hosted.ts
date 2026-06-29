/**
 * hosted.ts — Tier-2 hosted scan API.
 *
 * The lightest-effort integration for a service that wants stealth detection
 * with zero infra: it POSTs a view key and receives an `onIncoming` webhook per
 * detected payment. This is Tier 1 (`TreeScanner`) wrapped in a service — the
 * SAME multi-input scan core, no forked crypto.
 *
 * Privacy gradient: the view key LEAVES the integrator and reaches this host
 * (a privacy trade for convenience). It still cannot spend — a `ViewKey` is
 * structurally `{ bScan, bSpendPub }`, never `b_spend`. A fully-compromised host
 * leaks visibility, never funds.
 *
 * This class is the transport-agnostic core of the service. The HTTP binding
 * (Bun.serve / Express routes mapping POST→register and dispatch→fetch) is the
 * deployment skin and is intentionally not coupled here, so the dispatch logic
 * stays unit-testable without a socket.
 */

import { type ViewKey } from './stealth';
import { TreeScanner, type IndexerAdapter, type IncomingPayment } from './treewalk';

/** What an integrator POSTs to register for detection. */
export interface RegisterRequest {
  label: string;
  viewKey: { bScan: string; bSpendPub: string }; // bScan as decimal/hex string over the wire
  /** Where to deliver detected payments. */
  webhookUrl: string;
}

/** Delivers a detected payment to an integrator's webhook URL. */
export type WebhookDelivery = (url: string, payment: IncomingPayment) => void | Promise<void>;

/** Parse the wire form of a view key into the internal `ViewKey`. */
function parseViewKey(v: RegisterRequest['viewKey']): ViewKey {
  return {
    bScan: BigInt(v.bScan),
    bSpendPub: v.bSpendPub.toLowerCase(),
  };
}

export class HostedScanner {
  private readonly scanner: TreeScanner;
  private readonly webhooks = new Map<string, string>(); // label → webhookUrl

  constructor(
    adapter: IndexerAdapter,
    private readonly deliver: WebhookDelivery,
  ) {
    this.scanner = new TreeScanner(adapter);
  }

  /** Handle a `registerViewKey` request: store the webhook and wire detection. */
  register(req: RegisterRequest): { label: string; status: 'registered' } {
    this.webhooks.set(req.label, req.webhookUrl);
    this.scanner.registerViewKey(req.label, parseViewKey(req.viewKey), (payment) => {
      const url = this.webhooks.get(payment.label);
      if (url) void this.deliver(url, payment);
    });
    return { label: req.label, status: 'registered' };
  }

  /** Pull new batches and fan out detected payments to webhooks. */
  async poll(): Promise<IncomingPayment[]> {
    return this.scanner.sync();
  }

  /** Inbound history for a label (backs a hosted dashboard endpoint). */
  getHistory(label: string): IncomingPayment[] {
    return this.scanner.getHistory(label);
  }
}
