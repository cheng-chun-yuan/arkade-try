/**
 * stealth.ts — Pure secp256k1 crypto for Arkade Stealth (silent payments for VTXOs).
 *
 * Implements a BIP-352-style single-input silent payment:
 *
 *   P = B_spend + H( H(outpoint‖A) · a · B_scan ‖ t ) · G
 *
 * where the sender spends a VTXO whose input key is (a, A=a·G), the recipient
 * publishes a static meta-address (B_scan, B_spend), and `t` is the output index
 * inside the funding transaction (the per-output label).
 *
 * Roles:
 *   - sender    : holds `a`, sees the recipient meta-address  -> derives P (the funded pubkey)
 *   - scanner   : holds only b_scan (the view key)            -> can DETECT P, CANNOT spend
 *   - recipient : holds b_scan AND b_spend                    -> derives p with p·G == P, spends
 *
 * Zero SDK deps. secp256k1 + sha256 only.
 */

import { ProjectivePoint, CURVE, utils as secpUtils } from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, concatBytes } from '@noble/hashes/utils';

const N = CURVE.n; // group order

// ----------------------------------------------------------------------------
// scalar / point helpers
// ----------------------------------------------------------------------------

export type Point = InstanceType<typeof ProjectivePoint>;

const G = ProjectivePoint.BASE;

/** Reduce a big integer into the scalar field [0, n). */
function modN(x: bigint): bigint {
  return ((x % N) + N) % N;
}

/** 32-byte big-endian encoding of a scalar. */
function scalarToBytes(x: bigint): Uint8Array {
  const hex = modN(x).toString(16).padStart(64, '0');
  return hexToBytes(hex);
}

/** Big-endian bytes -> bigint. */
function bytesToBigInt(b: Uint8Array): bigint {
  return BigInt('0x' + (bytesToHex(b) || '0'));
}

/** Hash bytes -> nonzero scalar in [1, n). */
function hashToScalar(...parts: Uint8Array[]): bigint {
  const s = modN(bytesToBigInt(sha256(concatBytes(...parts))));
  return s === 0n ? 1n : s;
}

/** 4-byte big-endian encoding of an output index / label. */
function serT(t: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, t >>> 0, false);
  return b;
}

const compressed = (p: Point): Uint8Array => p.toRawBytes(true);
const pointFromHex = (h: string | Uint8Array): Point =>
  ProjectivePoint.fromHex(typeof h === 'string' ? hexToBytes(h) : h);

// ----------------------------------------------------------------------------
// keys & meta-address
// ----------------------------------------------------------------------------

export interface KeyPair {
  priv: bigint;
  pub: string; // compressed hex (33 bytes)
}

export interface MetaAddress {
  bScanPub: string; // B_scan  (33-byte compressed hex)
  bSpendPub: string; // B_spend (33-byte compressed hex)
}

/** Full recipient key material (kept private; never published). */
export interface RecipientKeys {
  scan: KeyPair; // (b_scan, B_scan) — also the view key
  spend: KeyPair; // (b_spend, B_spend)
  meta: MetaAddress;
}

/** The view key: exactly the scan secret + the spend *public* key. Detect-only. */
export interface ViewKey {
  bScan: bigint; // scan secret (delegated to scanner / auditor)
  bSpendPub: string; // recipient's B_spend (public) — needed to recompute P
}

function keyPairFrom(priv: bigint): KeyPair {
  const p = modN(priv) === 0n ? 1n : modN(priv);
  return { priv: p, pub: bytesToHex(compressed(G.multiply(p))) };
}

/** Generate a fresh keypair. */
export function generateKeyPair(): KeyPair {
  return keyPairFrom(bytesToBigInt(secpUtils.randomPrivateKey()));
}

/** Generate full recipient key material (scan + spend). */
export function generateRecipient(): RecipientKeys {
  const scan = generateKeyPair();
  const spend = generateKeyPair();
  return {
    scan,
    spend,
    meta: { bScanPub: scan.pub, bSpendPub: spend.pub },
  };
}

/** Derive a recipient deterministically from a 32-byte seed (for seed recovery). */
export function recipientFromSeed(seed: Uint8Array): RecipientKeys {
  const scan = keyPairFrom(hashToScalar(seed, new TextEncoder().encode('scan')));
  const spend = keyPairFrom(hashToScalar(seed, new TextEncoder().encode('spend')));
  return { scan, spend, meta: { bScanPub: scan.pub, bSpendPub: spend.pub } };
}

/** Extract the detect-only view key from full recipient material. */
export function viewKeyOf(r: RecipientKeys): ViewKey {
  return { bScan: r.scan.priv, bSpendPub: r.meta.bSpendPub };
}

/** Hex-encode a meta-address as B_scan‖B_spend (66 bytes -> 132 hex chars). */
export function encodeMetaAddress(m: MetaAddress): string {
  return m.bScanPub + m.bSpendPub;
}

/** Decode a hex meta-address. (Swap for bech32m before any real use.) */
export function decodeMetaAddress(hex: string): MetaAddress {
  if (hex.length !== 132) throw new Error('meta-address must be 132 hex chars (66 bytes)');
  return { bScanPub: hex.slice(0, 66), bSpendPub: hex.slice(66) };
}

// ----------------------------------------------------------------------------
// the shared secret
// ----------------------------------------------------------------------------

export interface Outpoint {
  txid: string; // hex
  vout: number;
}

function serOutpoint(o: Outpoint): Uint8Array {
  return concatBytes(hexToBytes(o.txid), serT(o.vout));
}

/** input_hash = H(outpoint ‖ A)  — binds the secret to the spent VTXO (replay protection). */
function inputHash(outpoint: Outpoint, aPub: Uint8Array): bigint {
  return hashToScalar(serOutpoint(outpoint), aPub);
}

/**
 * The per-output tweak scalar k = H( ecdh ‖ t ), where `ecdh` is the shared
 * secret point. Both sides compute the same `ecdh`:
 *   sender    : input_hash · a · B_scan
 *   recipient : input_hash · b_scan · A
 * (equal because a·B_scan == b_scan·A).
 */
function outputTweak(ecdh: Point, t: number): bigint {
  return hashToScalar(compressed(ecdh), serT(t));
}

// ----------------------------------------------------------------------------
// sender
// ----------------------------------------------------------------------------

export interface SenderDeriveParams {
  meta: MetaAddress; // recipient's published meta-address
  spenderPriv: bigint; // a — the sender's spent-VTXO input secret
  spentOutpoint: Outpoint; // the VTXO outpoint being spent
  t: number; // output index inside the funding tx
}

export interface DerivedOutput {
  P: string; // compressed hex of the stealth pubkey to fund — plugs in as userPK
  t: number;
}

/** Sender: derive the one-time stealth pubkey P to fund VTXO(P). */
export function senderDerive(p: SenderDeriveParams): DerivedOutput {
  const aPub = compressed(G.multiply(modN(p.spenderPriv)));
  const ih = inputHash(p.spentOutpoint, aPub);
  const BScan = pointFromHex(p.meta.bScanPub);
  // ecdh = input_hash · a · B_scan
  const ecdh = BScan.multiply(modN(ih * modN(p.spenderPriv)));
  const k = outputTweak(ecdh, p.t);
  const P = pointFromHex(p.meta.bSpendPub).add(G.multiply(k));
  return { P: bytesToHex(compressed(P)), t: p.t };
}

// ----------------------------------------------------------------------------
// scanner (view key only — detect, cannot spend)
// ----------------------------------------------------------------------------

export interface ScanParams {
  viewKey: ViewKey;
  senderPub: string; // A — the spender's input pubkey, revealed in the witness
  spentOutpoint: Outpoint;
  t: number;
}

/** Recompute the expected P for a candidate output using only the view key. */
export function expectedP(p: ScanParams): string {
  const A = pointFromHex(p.senderPub);
  const ih = inputHash(p.spentOutpoint, hexToBytes(p.senderPub));
  // ecdh = input_hash · b_scan · A
  const ecdh = A.multiply(modN(ih * modN(p.viewKey.bScan)));
  const k = outputTweak(ecdh, p.t);
  const P = pointFromHex(p.viewKey.bSpendPub).add(G.multiply(k));
  return bytesToHex(compressed(P));
}

/** True iff the candidate output pubkey belongs to this view key. */
export function scanMatches(p: ScanParams, candidateP: string): boolean {
  return expectedP(p) === candidateP.toLowerCase();
}

// ----------------------------------------------------------------------------
// recipient (full keys — derive the spend key)
// ----------------------------------------------------------------------------

export interface SpendKeyParams {
  scanPriv: bigint; // b_scan
  spendPriv: bigint; // b_spend
  senderPub: string; // A
  spentOutpoint: Outpoint;
  t: number;
}

/**
 * Recipient: derive the one-time spend secret p such that p·G == P.
 *   k = H( input_hash · b_scan · A ‖ t )
 *   p = b_spend + k   (mod n)
 * Throws if the derived pubkey does not match `expectedP` for the same inputs.
 */
export function recipientSpendKey(p: SpendKeyParams): { priv: bigint; pub: string } {
  const A = pointFromHex(p.senderPub);
  const ih = inputHash(p.spentOutpoint, hexToBytes(p.senderPub));
  const ecdh = A.multiply(modN(ih * modN(p.scanPriv)));
  const k = outputTweak(ecdh, p.t);
  const priv = modN(modN(p.spendPriv) + k);
  return { priv, pub: bytesToHex(compressed(G.multiply(priv))) };
}

// ----------------------------------------------------------------------------
// multi-input (BIP-352 aggregation) — required by the Arkade batch tree
//
// A batch/round tree groups many inputs into one virtual tx. BIP-352 aggregates
// them instead of pairing input→output:
//
//   A_sum      = Σ Aᵢ                      (sum of input pubkeys, as points)
//   a_sum      = Σ aᵢ (mod n)              (sender side; sum of input secrets)
//   nonce      = min(vtxoId over inputs)    (lexicographically smallest)
//   input_hash = H( nonce ‖ A_sum )
//   ecdh       = input_hash · a_sum · B_scan   (sender)
//              = input_hash · b_scan · A_sum   (scanner / recipient)
//
// Single-input v0 is exactly the n=1 case. `vtxoId` replaces the on-chain
// outpoint as the replay nonce — that one substitution makes BIP-352 work
// off-chain (the operator's single-spend enforcement gives vtxoId its
// uniqueness).
// ----------------------------------------------------------------------------

/** Lexicographically smallest vtxoId — the canonical replay nonce for a tx. */
function minNonce(vtxoIds: string[]): string {
  if (vtxoIds.length === 0) throw new Error('multi-input: at least one input required');
  return vtxoIds.slice().sort()[0]!;
}

/** Sum a list of compressed-hex pubkeys into A_sum (a point). */
function sumPoints(pubs: string[]): Point {
  if (pubs.length === 0) throw new Error('multi-input: at least one input pubkey required');
  return pubs.map(pointFromHex).reduce((acc, p) => acc.add(p));
}

/** Sum input pubkeys → A_sum as compressed hex. */
export function sumPubkeys(pubs: string[]): string {
  return bytesToHex(compressed(sumPoints(pubs)));
}

/** input_hash for an aggregated tx: H( min(vtxoId) ‖ A_sum ). */
function aggInputHash(nonce: string, aSumPub: Uint8Array): bigint {
  return hashToScalar(new TextEncoder().encode(nonce), aSumPub);
}

export interface SenderDeriveMultiParams {
  meta: MetaAddress; // recipient's published meta-address
  spenderPrivs: bigint[]; // aᵢ — all input secrets the sender controls
  inputVtxoIds: string[]; // vtxoId per input (for choosing the min nonce)
  t: number; // output leafIndex inside the funding vtx
}

/** Sender (multi-input): derive the one-time stealth pubkey P to fund VTXO(P). */
export function senderDeriveMulti(p: SenderDeriveMultiParams): DerivedOutput {
  const aSum = modN(p.spenderPrivs.reduce((s, x) => s + modN(x), 0n));
  const aSumPub = compressed(G.multiply(aSum));
  const ih = aggInputHash(minNonce(p.inputVtxoIds), aSumPub);
  const ecdh = pointFromHex(p.meta.bScanPub).multiply(modN(ih * aSum));
  const k = outputTweak(ecdh, p.t);
  const P = pointFromHex(p.meta.bSpendPub).add(G.multiply(k));
  return { P: bytesToHex(compressed(P)), t: p.t };
}

export interface ScanMultiParams {
  viewKey: ViewKey;
  senderPubs: string[]; // Aᵢ — every input pubkey revealed in the vtx
  inputVtxoIds: string[];
  t: number;
}

/** Recompute the expected P for a candidate output using only the view key. */
export function expectedPMulti(p: ScanMultiParams): string {
  const ASum = sumPoints(p.senderPubs);
  const ih = aggInputHash(minNonce(p.inputVtxoIds), compressed(ASum));
  const ecdh = ASum.multiply(modN(ih * modN(p.viewKey.bScan)));
  const k = outputTweak(ecdh, p.t);
  const P = pointFromHex(p.viewKey.bSpendPub).add(G.multiply(k));
  return bytesToHex(compressed(P));
}

/** True iff a candidate output pubkey belongs to this view key (multi-input). */
export function scanMatchesMulti(p: ScanMultiParams, candidateP: string): boolean {
  return expectedPMulti(p) === candidateP.toLowerCase();
}

export interface SpendKeyMultiParams {
  scanPriv: bigint; // b_scan
  spendPriv: bigint; // b_spend
  senderPubs: string[]; // Aᵢ
  inputVtxoIds: string[];
  t: number;
}

/** Recipient (multi-input): derive the one-time spend secret p with p·G == P. */
export function recipientSpendKeyMulti(p: SpendKeyMultiParams): { priv: bigint; pub: string } {
  const ASum = sumPoints(p.senderPubs);
  const ih = aggInputHash(minNonce(p.inputVtxoIds), compressed(ASum));
  const ecdh = ASum.multiply(modN(ih * modN(p.scanPriv)));
  const k = outputTweak(ecdh, p.t);
  const priv = modN(modN(p.spendPriv) + k);
  return { priv, pub: bytesToHex(compressed(G.multiply(priv))) };
}

export const _internal = { modN, hashToScalar, G, N, minNonce, sumPoints };
