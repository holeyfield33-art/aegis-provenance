import { randomUUID } from 'crypto';
import type { Origin, Span, SpanMeta, Trust } from './types.js';
import { signSpan, verifySpan } from './crypto/signing.js';
import { AegisSigningError } from './types.js';
import { getSigningKey } from './crypto/keys.js';

export function deriveTrust(origin: Origin): Trust {
  switch (origin) {
    case 'system':
    case 'user-session':
      return 'actionable';
    case 'tool-result':
    case 'untrusted-web':
    case 'untrusted-file':
    case 'memory':
    case 'model':
      return 'inert';
    default:
      return 'inert';
  }
}

export interface WrapSpanOptions {
  origin: Origin;
  content: string;
  meta?: Partial<Omit<SpanMeta, 'ingested_at'>>;
}

export function wrapSpan({ origin, content, meta }: WrapSpanOptions): Span {
  if (typeof content !== 'string') {
    throw new AegisSigningError(
      `Span content for origin '${origin}' must be a string, got ${content === null ? 'null' : typeof content}.`
    );
  }

  const now = new Date().toISOString();
  const span: Omit<Span, 'sig'> = {
    id: randomUUID(),
    origin,
    trust: deriveTrust(origin),
    content,
    meta: {
      ...meta,
      ingested_at: now
    }
  };

  try {
    const sig = signSpan(span, getSigningKey());
    return { ...span, sig };
  } catch (cause) {
    throw new AegisSigningError(`Failed to wrap span: ${cause instanceof Error ? cause.message : String(cause)}`);
  }
}

export interface SpanIntegrityResult {
  valid: boolean;
  reason?: string;
}

// Verify-on-use: the v2 signature covers id/origin/trust/source_uri/
// parent_span/ingested_at/content, so tampering with any of them (trust
// included) now breaks the signature directly. Trust is still re-derived from
// origin here as defense-in-depth — a belt-and-suspenders invariant that a
// span's stored trust must equal what its origin implies, independent of the
// signature layer.
export function verifySpanIntegrity(span: Span, publicKey: Uint8Array): SpanIntegrityResult {
  if (!verifySpan(span, publicKey)) {
    return { valid: false, reason: `Span ${span.id} failed signature verification.` };
  }

  const expectedTrust = deriveTrust(span.origin);
  if (span.trust !== expectedTrust) {
    return {
      valid: false,
      reason: `Span ${span.id} trust mismatch: stored '${span.trust}', derived '${expectedTrust}' from origin '${span.origin}'.`
    };
  }

  return { valid: true };
}
