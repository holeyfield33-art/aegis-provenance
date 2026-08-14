import { describe, expect, it } from 'vitest';
import { deriveTrust, wrapSpan } from '../src/ingest.js';
import type { Origin, Trust } from '../src/types.js';

const EXPECTED_TRUST: Record<Origin, Trust> = {
  system: 'actionable',
  'user-session': 'actionable',
  'tool-result': 'inert',
  'untrusted-web': 'inert',
  'untrusted-file': 'inert',
  memory: 'inert',
  model: 'inert'
};

describe('deriveTrust purity', () => {
  it('maps every origin to its documented trust level', () => {
    for (const [origin, trust] of Object.entries(EXPECTED_TRUST) as Array<[Origin, Trust]>) {
      expect(deriveTrust(origin)).toBe(trust);
    }
  });

  it('is deterministic: repeated calls with the same origin always agree, in any order', () => {
    const origins = Object.keys(EXPECTED_TRUST) as Origin[];
    const shuffled = [...origins].reverse();

    for (const origin of origins) {
      const first = deriveTrust(origin);
      // Interleave calls for other origins between repeated calls for this one
      // to rule out any hidden call-order or shared-state dependence.
      for (const other of shuffled) {
        if (other === origin) continue;
        deriveTrust(other);
      }
      const second = deriveTrust(origin);
      expect(second).toBe(first);
      expect(second).toBe(EXPECTED_TRUST[origin]);
    }
  });

  it('takes no input besides origin: an unrecognized origin value still falls back to inert, never actionable', () => {
    // deriveTrust's default case must fail closed. Cast past the Origin union
    // to simulate a value that reached this function without having passed
    // TypeScript's exhaustiveness check (e.g. deserialized from an older wire
    // format, or a caller bypassing types with `as any`).
    const unknownOrigin = 'from-the-future' as unknown as Origin;
    expect(deriveTrust(unknownOrigin)).toBe('inert');
  });

  it('wrapSpan ignores a caller-supplied trust field and always derives trust from origin', () => {
    // WrapSpanOptions has no `trust` field, so this can only be reached by a
    // caller that bypasses the type system (an untyped JS caller, or `as any`
    // at a module boundary). Aegis's entire escalation-resistance story rests
    // on trust never being caller-influenced, so prove it holds even here.
    const spoofed = {
      origin: 'untrusted-web',
      content: 'attacker-controlled content',
      trust: 'actionable'
    } as unknown as Parameters<typeof wrapSpan>[0];

    const span = wrapSpan(spoofed);
    expect(span.trust).toBe('inert');
    expect(span.trust).toBe(deriveTrust('untrusted-web'));
  });
});
