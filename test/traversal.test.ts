import { describe, expect, it } from 'vitest';
import { collectLeafStrings, hasCircularReference, TRAVERSAL_MAX_DEPTH } from '../src/traversal.js';

// Regression coverage for #41 (JSON-in-string provenance blind spot) and #44
// (unbounded attribution recursion). Both attribution.ts and egress.ts now
// share this single traversal, so these tests exercise the primitive
// directly; test/attribution.test.ts and test/egress.test.ts exercise it
// through the decision layer.

describe('collectLeafStrings', () => {
  it('collects plain nested string leaves', () => {
    const leaves = collectLeafStrings({ a: 'x', b: { c: 'y' }, d: ['z'] });
    expect(leaves).toContain('x');
    expect(leaves).toContain('y');
    expect(leaves).toContain('z');
  });

  it('parses JSON embedded in a string leaf and also keeps the raw string', () => {
    const leaves = collectLeafStrings({ payload: '{"to":"evil@example.com"}' });
    expect(leaves).toContain('{"to":"evil@example.com"}');
    expect(leaves).toContain('evil@example.com');
  });

  it('recovers a value nested behind double-escaped (double-serialized) JSON', () => {
    const inner = JSON.stringify({ bcc: 'evil@example.com' });
    const outer = JSON.stringify({ routing: inner });
    const leaves = collectLeafStrings({ options: outer });
    expect(leaves).toContain('evil@example.com');
  });

  it('does not drop a shared (non-circular) sub-object referenced from two branches', () => {
    const shared = { note: 'shared-value' };
    const leaves = collectLeafStrings({ a: shared, b: shared });
    expect(leaves.filter((s) => s === 'shared-value')).toHaveLength(2);
  });

  it('does not crash or hang on a deeply nested (but acyclic) structure', () => {
    let deep: unknown = 'bottom';
    for (let i = 0; i < 50_000; i += 1) {
      deep = [deep];
    }
    expect(() => collectLeafStrings(deep)).not.toThrow();
  });

  it('stops descending past the shared depth budget rather than collecting unbounded leaves', () => {
    let deep: unknown = 'bottom';
    for (let i = 0; i < 50; i += 1) {
      deep = [deep];
    }
    expect(collectLeafStrings(deep)).not.toContain('bottom');
    expect(TRAVERSAL_MAX_DEPTH).toBeLessThan(50);
  });
});

describe('hasCircularReference', () => {
  it('detects a true cycle', () => {
    const cyclic: Record<string, unknown> = { a: 1 };
    cyclic.self = cyclic;
    expect(hasCircularReference(cyclic)).toBe(true);
  });

  it('does not flag a DAG with a shared (non-circular) sub-object', () => {
    const shared = { note: 'shared' };
    expect(hasCircularReference({ a: shared, b: shared })).toBe(false);
  });

  it('does not crash on a deeply nested (but acyclic) structure', () => {
    let deep: unknown = 'bottom';
    for (let i = 0; i < 50_000; i += 1) {
      deep = [deep];
    }
    expect(() => hasCircularReference(deep)).not.toThrow();
  });
});
