/**
 * resolver.ts — static `name@domain → meta-address` lookup, BIP-353-shaped.
 *
 * BIP-353 publishes payment instructions in DNS TXT records at
 *   ${name}.user._bitcoin-payment.${domain}
 * with a `bitcoin:` URI value. We reuse that shape, carrying the stealth
 * meta-address as a custom `ark-sp` parameter. v0 is an in-memory map; a real
 * deployment swaps `resolve` for a DNSSEC-validated TXT lookup with no other
 * code change.
 */

import { type MetaAddress, encodeMetaAddress, decodeMetaAddress } from './stealth';

const PREFIX = '_bitcoin-payment';
const PARAM = 'ark-sp'; // Arkade silent-payment meta-address (hex; bech32m later)

export interface Name {
  user: string; // e.g. "treasury"
  domain: string; // e.g. "arkade.btc"
}

/** Parse "treasury@arkade.btc" into its parts. */
export function parseName(addr: string): Name {
  const at = addr.indexOf('@');
  if (at <= 0 || at === addr.length - 1) throw new Error(`invalid name: ${addr}`);
  return { user: addr.slice(0, at), domain: addr.slice(at + 1) };
}

/** The DNS name a BIP-353 client would query. */
export function txtRecordName(addr: string): string {
  const { user, domain } = parseName(addr);
  return `${user}.user.${PREFIX}.${domain}`;
}

/** The TXT record *value* carrying a meta-address. */
export function txtRecordValue(meta: MetaAddress): string {
  return `bitcoin:?${PARAM}=${encodeMetaAddress(meta)}`;
}

/** A full BIP-353-shaped TXT record (name + value). */
export function txtRecord(addr: string, meta: MetaAddress): { name: string; value: string } {
  return { name: txtRecordName(addr), value: txtRecordValue(meta) };
}

/** Pull the meta-address back out of a TXT value. */
export function parseTxtValue(value: string): MetaAddress {
  const m = value.match(new RegExp(`[?&]${PARAM}=([0-9a-fA-F]+)`));
  if (!m) throw new Error(`no ${PARAM} parameter in TXT value`);
  return decodeMetaAddress(m[1]!.toLowerCase());
}

/** Static resolver: register names and resolve them to meta-addresses. */
export class StaticResolver {
  private records = new Map<string, MetaAddress>();

  /** Publish a name → meta-address mapping. */
  register(addr: string, meta: MetaAddress): void {
    this.records.set(addr.toLowerCase(), meta);
  }

  /** Resolve "name@domain" → meta-address (throws if unknown). */
  resolve(addr: string): MetaAddress {
    const meta = this.records.get(addr.toLowerCase());
    if (!meta) throw new Error(`unresolved name: ${addr}`);
    return meta;
  }

  /** The TXT record a DNS server would serve for a registered name. */
  txtRecord(addr: string): { name: string; value: string } {
    return txtRecord(addr, this.resolve(addr));
  }
}
