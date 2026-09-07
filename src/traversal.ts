// Shared guarded leaf-string traversal (#41).
//
// Before this module, attribution.ts (`extractStrings`) and egress.ts
// (`collectLeafStrings`) each hand-rolled their own recursive walk of a tool
// call's `args`, and the two had drifted: egress.ts parsed JSON embedded in
// string leaves (including double-escaped payloads) and capped recursion
// depth; attribution.ts did neither. That divergence was a real bug, not just
// duplication — a destination smuggled inside a JSON-stringified sub-field
// was extracted correctly by egress.ts's destination-authorization path but
// invisible to attribution.ts's provenance/content-sensitivity checks, since
// the latter treated the whole JSON-wrapped blob as one opaque value that
// essentially never matches a span verbatim. That silently defeated the
// "arguments originate only from inert spans" gate for any sensitive tool
// other than the two (`send_email`, `http_post`) that get bespoke egress
// treatment (`delete_file`, `transfer_funds`, `set_permission`, custom
// tools). Separately, the unbounded recursion in both hand-rolled walkers
// (well, all but egress.ts's, which already had a depth guard) was a
// stack-overflow DoS via a deeply nested but acyclic `tool_args` payload.
//
// This module is now the SINGLE traversal both call sites use, so the two
// checks can never again silently disagree about what a call's arguments
// contain.
//
// Deliberately NOT used by src/testing/tool-oracle.ts: the oracle's design
// rules (see its file header) require it to be an independent implementation
// that never imports Aegis code, so its own `collectStrings` stays separate
// by design — two independent extractors agreeing is corroboration, not
// circularity.

const MAX_DEPTH = 8;

/** Depth budget shared by every traversal in this module — keeps a
 * pathological (deeply nested, or JSON-in-string recursively re-wrapped)
 * `tool_args` payload from crashing the process instead of just being
 * truncated at a bounded, generous depth. */
export const TRAVERSAL_MAX_DEPTH = MAX_DEPTH;

/**
 * True iff `value` contains a genuine cycle (an object reachable from
 * itself), as opposed to a DAG with a shared sub-object referenced from more
 * than one place (valid JSON, must not be rejected). `ancestors` tracks only
 * the current recursion path and is unwound on the way back up, so
 * revisiting a shared reference from a sibling branch is never flagged.
 * Depth-guarded so a very deep (but acyclic) structure returns `false`
 * instead of overflowing the stack — safe because a real cycle always
 * revisits an ancestor within a handful of steps (bounded by the number of
 * distinct objects in the cycle), well inside any reasonable depth budget.
 */
export function hasCircularReference(value: unknown, depth = 0, ancestors: Set<object> = new Set()): boolean {
  if (depth > MAX_DEPTH || value === null || typeof value !== 'object') {
    return false;
  }
  if (ancestors.has(value)) {
    return true;
  }

  ancestors.add(value);
  const children = Array.isArray(value) ? value : Object.values(value as Record<string, unknown>);
  const circular = children.some((child) => hasCircularReference(child, depth + 1, ancestors));
  ancestors.delete(value);
  return circular;
}

/**
 * Collect every string leaf reachable from `value`: descends through objects
 * and arrays, and ALSO parses any string leaf that is itself a JSON
 * object/array and descends into it — recovering values smuggled via a
 * stringified or double-escaped payload. The raw string is always kept too,
 * so a destination that sits in the serialized text is matched even when the
 * JSON does not re-parse.
 *
 * Depth-guarded (`TRAVERSAL_MAX_DEPTH`) against runaway or maliciously deep
 * input. Cycle-guarded via an ancestor-path set (unwound on the way back up),
 * so — like `hasCircularReference` — a DAG with a shared, non-cyclic
 * sub-object is traversed fully rather than having its second occurrence
 * silently dropped.
 */
export function collectLeafStrings(value: unknown, depth = 0, ancestors: Set<object> = new Set()): string[] {
  if (depth > MAX_DEPTH || value === null || value === undefined) {
    return [];
  }
  if (typeof value === 'string') {
    const out = [value];
    const trimmed = value.trim();
    if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
      try {
        const parsed = JSON.parse(trimmed);
        if (parsed && typeof parsed === 'object') {
          out.push(...collectLeafStrings(parsed, depth + 1, ancestors));
        }
      } catch {
        // Not valid JSON — the raw string is already captured.
      }
    }
    return out;
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return [String(value)];
  }
  if (typeof value === 'object') {
    if (ancestors.has(value as object)) {
      return [];
    }
    ancestors.add(value as object);
    const children = Array.isArray(value) ? value : Object.values(value as Record<string, unknown>);
    const result = children.flatMap((child) => collectLeafStrings(child, depth + 1, ancestors));
    ancestors.delete(value as object);
    return result;
  }
  return [];
}
