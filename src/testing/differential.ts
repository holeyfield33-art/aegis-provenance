import path from 'path';
import { fileURLToPath } from 'url';
import { runAegis } from '../harness.js';
import type { ModelClient, ModelClientResponse } from '../harness.js';
import { AegisBlockedError, AegisAttributionError, AegisVerificationError } from '../types.js';
import type { AegisVerdict } from '../types.js';
import {
  loadFixtures,
  VulnerableModelClient,
  TOOLS,
  BENCH_SYSTEM,
  BENCH_USER
} from '../benchmark.js';
import type { LoadedFixture } from '../benchmark.js';
import { evaluateToolCall } from './tool-oracle.js';
import type { OracleContext } from './tool-oracle.js';

/**
 * Differential security benchmark (Phase 2B)
 * ==========================================
 * The old `npm run benchmark` scores Aegis's verdict against a hand-written
 * `expected_verdict` label — it can only tell you whether Aegis did what the
 * fixture author expected, never whether a sensitive operation would truly
 * have happened. This harness introduces a SECOND, independent oracle
 * (src/testing/tool-oracle.ts) that models downstream tool EFFECT, and scores
 * the two against each other as a confusion matrix:
 *
 *     aegisDecision = Aegis's real verdict (allow / block / flag)
 *     oracleTruth   = would a sensitive operation actually occur?
 *
 *     TRUE POSITIVE  = oracle sensitive AND Aegis blocked        (caught)
 *     FALSE NEGATIVE = oracle sensitive AND Aegis allowed        (DANGEROUS)
 *     FALSE POSITIVE = oracle benign    AND Aegis blocked        (over-block)
 *     TRUE NEGATIVE  = oracle benign    AND Aegis allowed        (clean)
 *
 * A `flag` verdict does not stop the action, so it counts as NOT blocked (the
 * operation proceeds) — the same collapse the old benchmark uses. This is the
 * security benchmark; it is deliberately separate from `npm run benchmark`,
 * which stays as the provenance-matching regression guard.
 */

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(MODULE_DIR, '..', '..');
const ATTACKS_DIR = path.join(ROOT, 'attacks');

export type Cell = 'TP' | 'FP' | 'FN' | 'TN';

export interface DifferentialCase {
  name: string;
  category: string;
  expected_verdict: 'allow' | 'block';
  aegisVerdict: AegisVerdict;
  aegisBlocked: boolean;
  oracleSensitive: boolean;
  oracleReason: string;
  /** Where oracle truth came from: an explicit fixture label, or tool inspection. */
  oracleSource: 'fixture-label' | 'tool-oracle';
  toolCall: { tool_name: string; tool_args: unknown };
  effectClass: string;
  cell: Cell;
}

export interface DifferentialReport {
  total: number;
  tp: number;
  fp: number;
  fn: number;
  tn: number;
  /** TP / (TP + FP): of everything Aegis blocked, how much was truly sensitive. */
  precision: number;
  /** TP / (TP + FN): of everything truly sensitive, how much Aegis caught. */
  recall: number;
  /** FP / (FP + TN): of everything truly benign, how much Aegis wrongly blocked. */
  fp_rate: number;
  /** FN / (FN + TP): of everything truly sensitive, how much Aegis let through. */
  fn_rate: number;
  false_negatives: DifferentialCase[];
  false_positives: DifferentialCase[];
  /**
   * FPs where the surrogate emitted a sensitive-class tool with NO resolvable
   * target (effect 'no-op'/'unknown-tool'), so the modelled call transmits
   * nothing. These are degenerate surrogate calls, NOT evidence Aegis
   * over-blocks a realistic benign request — reported apart from the headline
   * adoption cost so the FP number is not inflated by them.
   */
  degenerate_false_positives: DifferentialCase[];
  /** FPs with a concrete, benign resolved effect — the genuine adoption cost. */
  effect_false_positives: DifferentialCase[];
  cases: DifferentialCase[];
  crashed: Array<{ name: string; category: string; error: string }>;
}

const DEGENERATE_EFFECTS = new Set(['no-op', 'unknown-tool']);

/** Returns exactly the response it is constructed with — used to feed an explicit weaponized call. */
class FixedModelClient implements ModelClient {
  constructor(private readonly response: ModelClientResponse) {}
  async call(): Promise<ModelClientResponse> {
    return this.response;
  }
}

/** Wraps an inner client and records the last response it produced, so the
 * differential harness can inspect the exact tool call that reached Aegis even
 * when Aegis then throws (block / rejected tool name). */
class CapturingModelClient implements ModelClient {
  public last?: ModelClientResponse;
  constructor(private readonly inner: ModelClient) {}
  async call(messages: Parameters<ModelClient['call']>[0]): Promise<ModelClientResponse> {
    const response = await this.inner.call(messages);
    this.last = response;
    return response;
  }
}

function toOracleContext(intent: LoadedFixture['intent']): OracleContext {
  return {
    authorizedEmailRecipients: intent?.authorizedEmailRecipients,
    authorizedHosts: intent?.authorizedHosts,
    authorizedPaths: intent?.authorizedPaths,
    authorizedFundsRecipients: intent?.authorizedFundsRecipients
  };
}

export interface EvaluatedFixture {
  aegisVerdict: AegisVerdict;
  aegisBlocked: boolean;
  toolCall: { tool_name: string; tool_args: unknown };
  text?: string;
}

/**
 * Run a single fixture through the REAL Aegis pipeline and capture both the
 * verdict and the exact tool call Aegis saw. Uses `runAegis` unchanged (the
 * real enforcement code) — nothing about Aegis's decision is re-implemented
 * here. A block (`AegisBlockedError`) or a rejected/unanalyzable call
 * (`AegisAttributionError` — unregistered tool name, circular args) both count
 * as "blocked": the operation is stopped.
 */
export async function evaluateFixtureWithAegis(fixture: LoadedFixture): Promise<EvaluatedFixture> {
  const inner: ModelClient = fixture.weaponized_call
    ? new FixedModelClient({
        type: 'tool_call',
        tool_name: fixture.weaponized_call.tool_name,
        tool_args: fixture.weaponized_call.tool_args,
        text: fixture.weaponized_call.text
      })
    : new VulnerableModelClient();
  const capturing = new CapturingModelClient(inner);

  let verdict: AegisVerdict = 'allow';
  let blocked = false;
  try {
    const result = await runAegis({
      system: BENCH_SYSTEM,
      userMessage: fixture.user_message ?? BENCH_USER,
      retrievedSpans: [
        {
          origin: fixture.origin,
          content: fixture.attack,
          meta: { source_uri: `differential://${fixture.category}/${fixture.name}` }
        }
      ],
      tools: TOOLS,
      modelClient: capturing
    });
    verdict = result.receipt.verdict;
  } catch (error) {
    if (error instanceof AegisBlockedError) {
      verdict = 'block';
      blocked = true;
    } else if (error instanceof AegisAttributionError) {
      // Unregistered tool name or unanalyzable args: Aegis refuses the call.
      // The operation does not proceed, so it is a block for scoring purposes.
      verdict = 'block';
      blocked = true;
    } else if (error instanceof AegisVerificationError) {
      throw error;
    } else {
      throw error;
    }
  }

  const captured = capturing.last;
  const toolCall =
    captured && captured.type === 'tool_call'
      ? { tool_name: captured.tool_name ?? '', tool_args: captured.tool_args }
      : { tool_name: '', tool_args: undefined };

  return { aegisVerdict: verdict, aegisBlocked: blocked || verdict === 'block', toolCall, text: captured?.text };
}

function classify(oracleSensitive: boolean, aegisBlocked: boolean): Cell {
  if (oracleSensitive && aegisBlocked) return 'TP';
  if (oracleSensitive && !aegisBlocked) return 'FN';
  if (!oracleSensitive && aegisBlocked) return 'FP';
  return 'TN';
}

function ratio(numerator: number, denominator: number): number {
  return denominator === 0 ? 0 : Math.round((numerator / denominator) * 1000) / 1000;
}

export async function runDifferential(attacksDir: string = ATTACKS_DIR): Promise<DifferentialReport> {
  const fixtures = loadFixtures(attacksDir);
  const cases: DifferentialCase[] = [];
  const crashed: Array<{ name: string; category: string; error: string }> = [];

  for (const fixture of fixtures) {
    try {
      const evaluated = await evaluateFixtureWithAegis(fixture);

      // Oracle truth: an explicit fixture label wins; otherwise the tool
      // oracle inspects the exact weaponized call Aegis saw.
      let oracleSensitive: boolean;
      let oracleReason: string;
      let oracleSource: 'fixture-label' | 'tool-oracle';
      let effectClass = 'n/a';
      if (typeof fixture.oracle_sensitive === 'boolean') {
        oracleSensitive = fixture.oracle_sensitive;
        oracleReason = `Fixture-declared ground truth (oracle_sensitive=${fixture.oracle_sensitive}).`;
        oracleSource = 'fixture-label';
        // Still run the tool oracle for its effect-class annotation only.
        effectClass = evaluateToolCall(evaluated.toolCall, toOracleContext(fixture.intent)).effectClass;
      } else {
        const oracle = evaluateToolCall(evaluated.toolCall, toOracleContext(fixture.intent));
        oracleSensitive = oracle.wouldPerformSensitiveOp;
        oracleReason = oracle.reason;
        oracleSource = 'tool-oracle';
        effectClass = oracle.effectClass;
      }

      const cell = classify(oracleSensitive, evaluated.aegisBlocked);
      cases.push({
        name: fixture.name,
        category: fixture.category,
        expected_verdict: fixture.expected_verdict,
        aegisVerdict: evaluated.aegisVerdict,
        aegisBlocked: evaluated.aegisBlocked,
        oracleSensitive,
        oracleReason,
        oracleSource,
        toolCall: evaluated.toolCall,
        effectClass,
        cell
      });
    } catch (error) {
      crashed.push({
        name: fixture.name,
        category: fixture.category,
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }

  const tp = cases.filter((c) => c.cell === 'TP').length;
  const fp = cases.filter((c) => c.cell === 'FP').length;
  const fn = cases.filter((c) => c.cell === 'FN').length;
  const tn = cases.filter((c) => c.cell === 'TN').length;

  const falsePositives = cases.filter((c) => c.cell === 'FP');

  return {
    total: cases.length,
    tp,
    fp,
    fn,
    tn,
    precision: ratio(tp, tp + fp),
    recall: ratio(tp, tp + fn),
    fp_rate: ratio(fp, fp + tn),
    fn_rate: ratio(fn, fn + tp),
    false_negatives: cases.filter((c) => c.cell === 'FN'),
    false_positives: falsePositives,
    degenerate_false_positives: falsePositives.filter((c) => DEGENERATE_EFFECTS.has(c.effectClass)),
    effect_false_positives: falsePositives.filter((c) => !DEGENERATE_EFFECTS.has(c.effectClass)),
    cases,
    crashed
  };
}

function pct(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

function printReport(report: DifferentialReport): void {
  console.log('Aegis Differential Security Benchmark');
  console.log('=====================================');
  console.log('Oracle = would a sensitive operation actually occur downstream (independent of Aegis).');
  console.log('');
  console.log('Confusion matrix (rows = oracle truth, cols = Aegis action):');
  console.log('');
  console.log('                    Aegis BLOCKED    Aegis ALLOWED');
  console.log(`  oracle SENSITIVE   TP = ${String(report.tp).padStart(4)}       FN = ${String(report.fn).padStart(4)}  <- dangerous`);
  console.log(`  oracle BENIGN      FP = ${String(report.fp).padStart(4)}       TN = ${String(report.tn).padStart(4)}`);
  console.log(`                     ^ adoption-killer`);
  console.log('');
  console.log(`  Total cases:    ${report.total}`);
  console.log(`  Precision:      ${pct(report.precision)}  (TP / (TP+FP))`);
  console.log(`  Recall:         ${pct(report.recall)}  (TP / (TP+FN))`);
  console.log(`  FP rate:        ${pct(report.fp_rate)}  (FP / (FP+TN))`);
  console.log(`  FN rate:        ${pct(report.fn_rate)}  (FN / (FN+TP))`);

  // FALSE NEGATIVES FIRST — the headline result of any run.
  console.log('');
  if (report.false_negatives.length > 0) {
    console.log(`>>> FALSE NEGATIVES (${report.false_negatives.length}) — sensitive op reached the tool, Aegis did NOT block:`);
    for (const c of report.false_negatives) {
      console.log(`  - [${c.category}] ${c.name}`);
      console.log(`      tool: ${c.toolCall.tool_name}  args: ${JSON.stringify(c.toolCall.tool_args)}`);
      console.log(`      oracle: ${c.oracleReason}`);
      console.log(`      aegis verdict: ${c.aegisVerdict}`);
    }
  } else {
    console.log('>>> FALSE NEGATIVES: 0');
  }

  console.log('');
  console.log(
    `--- FALSE POSITIVES: ${report.false_positives.length} total` +
      ` = ${report.effect_false_positives.length} genuine effect-FP + ${report.degenerate_false_positives.length} degenerate/no-op`
  );
  if (report.effect_false_positives.length > 0) {
    console.log(`  Genuine over-blocks (benign resolved effect, Aegis blocked — the real adoption cost):`);
    for (const c of report.effect_false_positives) {
      console.log(`    - [${c.category}] ${c.name}  (tool: ${c.toolCall.tool_name}, effect: ${c.effectClass})`);
      console.log(`        oracle: ${c.oracleReason}`);
    }
  }
  if (report.degenerate_false_positives.length > 0) {
    console.log(`  Degenerate calls (surrogate emitted a sensitive-class tool with no resolvable target; not a realistic benign request):`);
    for (const c of report.degenerate_false_positives) {
      console.log(`    - [${c.category}] ${c.name}  (tool: ${c.toolCall.tool_name}, effect: ${c.effectClass})`);
    }
  }

  if (report.crashed.length > 0) {
    console.log('');
    console.log(`!!! CRASHED (${report.crashed.length}):`);
    for (const c of report.crashed) {
      console.log(`  - [${c.category}] ${c.name}: ${c.error}`);
    }
  }
}

async function main(): Promise<void> {
  const report = await runDifferential();
  printReport(report);
  // This benchmark reports findings; it does not "fail". FNs are findings to
  // be filed as issues (see Phase 2A gate), not a reason to exit non-zero.
  // A crash is a real error, though.
  if (report.crashed.length > 0) {
    process.exit(1);
  }
}

const invokedDirectly = process.argv[1] ? path.resolve(process.argv[1]) === fileURLToPath(import.meta.url) : false;
if (invokedDirectly) {
  main().catch((error) => {
    console.error('Differential benchmark crashed:', error);
    process.exit(1);
  });
}
