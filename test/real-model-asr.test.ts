import { describe, expect, it } from 'vitest';
import { aggregateAsr } from '../src/testing/real-model-asr.js';
import type { AsrCell } from '../src/testing/real-model-asr.js';

/**
 * Unit tests for the pure aggregation of the Phase 2C real-model ASR harness.
 * The live model run needs an endpoint + key and is not exercised here; this
 * verifies the metric math (baseline vs aegis ASR, FP rate, bypass rate,
 * latency/overhead medians, error exclusion) on hand-built cells.
 */

function cell(overrides: Partial<AsrCell>): AsrCell {
  return {
    model: 'test-model',
    fixture: 'cat/name',
    category: 'cat',
    kind: 'attack',
    baseline_tool: null,
    baseline_sensitive: false,
    baseline_latency_ms: 0,
    aegis_verdict: 'allow',
    aegis_blocked: false,
    aegis_tool: null,
    aegis_success: false,
    aegis_latency_ms: 0,
    aegis_model_ms: 0,
    enforcement_overhead_ms: 0,
    error: null,
    ...overrides
  };
}

describe('aggregateAsr', () => {
  it('computes baseline vs aegis ASR and bypass rate from oracle-scored cells', () => {
    const cells: AsrCell[] = [
      // baseline sensitive + aegis blocked => caught (counts to baseline ASR, not aegis)
      cell({ baseline_sensitive: true, aegis_blocked: true, aegis_success: false, aegis_latency_ms: 100, enforcement_overhead_ms: 2 }),
      // baseline sensitive + aegis allowed sensitive => bypass (counts to both)
      cell({ baseline_sensitive: true, aegis_blocked: false, aegis_success: true, aegis_latency_ms: 200, enforcement_overhead_ms: 4 }),
      // baseline benign (model refused) + aegis benign
      cell({ baseline_sensitive: false, aegis_blocked: false, aegis_success: false, aegis_latency_ms: 300, enforcement_overhead_ms: 6 }),
      // baseline sensitive + aegis blocked => caught
      cell({ baseline_sensitive: true, aegis_blocked: true, aegis_success: false, aegis_latency_ms: 400, enforcement_overhead_ms: 8 })
    ];
    const s = aggregateAsr(cells)[0]!;
    expect(s.n_attack).toBe(4);
    expect(s.baseline_asr).toBeCloseTo(3 / 4); // 3 of 4 baseline sensitive
    expect(s.aegis_asr).toBeCloseTo(1 / 4); // 1 of 4 slipped through
    expect(s.bypass_rate).toBeCloseTo(1 / 4);
    expect(s.p50_latency_ms).toBeCloseTo((200 + 300) / 2); // median of 100,200,300,400
    expect(s.overhead_ms).toBeCloseTo((4 + 6) / 2);
  });

  it('measures FP rate over benign cells only', () => {
    const cells: AsrCell[] = [
      cell({ kind: 'attack', baseline_sensitive: true, aegis_blocked: true }),
      cell({ kind: 'benign', fixture: 'benign/a', aegis_blocked: true }), // FP
      cell({ kind: 'benign', fixture: 'benign/b', aegis_blocked: false }),
      cell({ kind: 'benign', fixture: 'benign/c', aegis_blocked: false })
    ];
    const s = aggregateAsr(cells)[0]!;
    expect(s.n_attack).toBe(1);
    expect(s.n_benign).toBe(3);
    expect(s.fp_rate).toBeCloseTo(1 / 3);
  });

  it('excludes errored cells from denominators and counts them', () => {
    const cells: AsrCell[] = [
      cell({ baseline_sensitive: true, aegis_success: true }),
      cell({ error: 'format: bad envelope' }),
      cell({ kind: 'benign', fixture: 'benign/x', error: 'network' })
    ];
    const s = aggregateAsr(cells)[0]!;
    expect(s.n_attack).toBe(1); // the errored attack cell excluded
    expect(s.n_benign).toBe(0);
    expect(s.errored).toBe(2);
    expect(s.baseline_asr).toBeCloseTo(1);
    expect(s.fp_rate).toBeNull(); // no scored benign cells
  });

  it('separates metrics per model', () => {
    const cells: AsrCell[] = [
      cell({ model: 'A', baseline_sensitive: true, aegis_success: true }),
      cell({ model: 'B', baseline_sensitive: true, aegis_success: false, aegis_blocked: true })
    ];
    const summaries = aggregateAsr(cells);
    expect(summaries.map((s) => s.model)).toEqual(['A', 'B']);
    expect(summaries[0]!.aegis_asr).toBeCloseTo(1);
    expect(summaries[1]!.aegis_asr).toBeCloseTo(0);
  });
});
