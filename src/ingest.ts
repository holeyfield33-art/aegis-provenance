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

// Verify-on-use: the signature covers origin/source_uri/ingested_at/content,
// but trust is derived state — it must be recomputed from origin here, never
// read back from the stored field, or a wire-tampered span could carry an
// escalated trust value past a valid signature.
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
