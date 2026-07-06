import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256Hex } from './hash.js';
import type { Receipt, Span } from '../types.js';

const encoder = new TextEncoder();

// Must round-trip through JSON.stringify/JSON.parse: undefined-valued object
// keys are omitted (JSON drops them on serialization) and undefined array
// items become null (JSON.stringify's behaviour), so a receipt hashed before
// persistence re-hashes identically after reload.
export function stableStringify(value: unknown): string {
  if (value === undefined) {
    return 'null';
  }

  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(',')}]`;
  }

  const record = value as Record<string, unknown>;
  const keys = Object.keys(record)
    .filter((key) => record[key] !== undefined)
    .sort();
  const entries = keys.map((key) => `${JSON.stringify(key)}:${stableStringify(record[key])}`);
  return `{${entries.join(',')}}`;
}

export function canonicalSpanPayload(span: Omit<Span, 'sig'>): Uint8Array {
  const origin = span.origin;
  const sourceUri = span.meta.source_uri ?? '';
  const ingestedAt = span.meta.ingested_at;
  const contentHash = sha256Hex(encoder.encode(span.content));
  const parts = [origin, sourceUri, ingestedAt, contentHash];
  const joined = parts.join('\u0000');
  return encoder.encode(joined);
}

export function signSpan(span: Omit<Span, 'sig'>, privateKey: Uint8Array): string {
  try {
    const payload = canonicalSpanPayload(span);
    const signature = ed25519.sign(payload, privateKey);
    return Buffer.from(signature).toString('hex');
  } catch (cause) {
    throw new Error(`Failed to sign span: ${cause instanceof Error ? cause.message : String(cause)}`);
  }
}

export function verifySpan(span: Span, publicKey: Uint8Array): boolean {
  try {
    const payload = canonicalSpanPayload({
      id: span.id,
      origin: span.origin,
      trust: span.trust,
      content: span.content,
      meta: span.meta
    });
    const signature = Uint8Array.from(Buffer.from(span.sig, 'hex'));
    return ed25519.verify(signature, payload, publicKey);
  } catch {
    return false;
  }
}

export function canonicalReceiptPayload(receipt: Omit<Receipt, 'receipt_hash'>): Uint8Array {
  const normalizedAction = stableStringify(receipt.model_action);
  const normalizedAttribution = stableStringify(receipt.attribution);
  const fields = [
    receipt.request_id,
    receipt.ts,
    receipt.span_ids.join(','),
    normalizedAction,
    normalizedAttribution,
    receipt.verdict,
    receipt.reason,
    receipt.prev_receipt_hash
  ];
  return encoder.encode(fields.join('\u0000'));
}

export function hashReceipt(receipt: Omit<Receipt, 'receipt_hash'>): string {
  return sha256Hex(canonicalReceiptPayload(receipt));
}
