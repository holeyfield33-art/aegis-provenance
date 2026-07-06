import { randomUUID } from 'crypto';
import type { Origin, Span, SpanMeta, Trust } from './types.js';
import { signSpan } from './crypto/signing.js';
import { AegisSigningError } from './types.js';
import { getSigningKey } from './crypto/keys.js';

function deriveTrust(origin: Origin): Trust {
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
