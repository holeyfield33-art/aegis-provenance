// Egress destination authorization.
// ==================================
//
// Aegis's original enforcement decided a sensitive action from provenance
// substring matching and content heuristics alone. That leaves a whole class
// of exfiltration open: a call that carries an *authorized* recipient plus one
// or more *extra* destinations the user never asked for (a BCC/CC, a nested
// routing field, a JSON-in-string blob, a header-injected `Bcc:` line, a CSV
// list, an array element, an encoded/homoglyph address). The authorized
// recipient makes the call look intentional; the extra destination is the
// leak. Substring provenance can't catch it, because the extra destination
// need not appear byte-for-byte in any span.
//
// This module closes that gap structurally (issues #27/#28/#29). It extracts
// EVERY destination a downstream tool would actually consume — traversing
// nested objects/arrays, parsing JSON embedded in string fields (including
// double-escaped), splitting comma/newline-separated lists, and folding
// homoglyphs / decoding base64/hex/rot13/percent-encoding — and requires each
// one to be positively justified by the user's own session. Anything the user
// did not authorize is treated as an off-intent send and blocked.
//
// It is deliberately an INDEPENDENT implementation from the differential tool
// oracle (src/testing/tool-oracle.ts). The oracle must never import Aegis, and
// Aegis must never import the oracle — otherwise the differential benchmark
// would be measuring a tautology. Two independent extractors agreeing on what a
// call transmits is corroboration, not circularity.

import type { Span } from './types.js';
import { foldConfusables, stripInvisible, expandDecodedCandidates } from './normalize.js';

const MAX_DEPTH = 8;

// Email + URL shapes. Local, not shared with the oracle by design.
const EMAIL_PATTERN = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
const URL_PATTERN = /https?:\/\/[^\s"'<>)\]}]+/gi;

export interface Destinations {
  emails: Set<string>;
  hosts: Set<string>;
}

function emptyDestinations(): Destinations {
  return { emails: new Set<string>(), hosts: new Set<string>() };
}

/** Percent-decode a string, but only when it actually changes and stays valid;
 * a malformed sequence returns the input unchanged (never throws). */
function tryPercentDecode(value: string): string | null {
  if (!value.includes('%')) {
    return null;
  }
  try {
    const decoded = decodeURIComponent(value);
    return decoded === value ? null : decoded;
  } catch {
    return null;
  }
}

/**
 * Lossless surface forms of a string, used when EXTRACTING the destinations a
 * downstream tool would actually consume: the raw string, its
 * invisible-stripped + homoglyph-folded form, and its percent-decoded form.
 *
 * These transforms only ever reveal an address that is genuinely present —
 * they never invent one. Base64/hex/rot13 decoding is deliberately NOT applied
 * here: a real mailer would not send to a base64 blob either, so decoding it
 * during extraction would conjure a recipient the tool never has, and (since a
 * decoded plaintext address is itself email-shaped) would fabricate phantom
 * destinations. Recovering an address that was encoded inside untrusted data is
 * handled on the SPAN side by `destinationTracesToTrust`, which decodes the
 * span, not the call.
 */
function extractionForms(value: string): string[] {
  const forms = new Set<string>([value]);
  forms.add(foldConfusables(stripInvisible(value)));

  const percent = tryPercentDecode(value);
  if (percent !== null) {
    forms.add(percent);
    forms.add(foldConfusables(stripInvisible(percent)));
  }

  return Array.from(forms);
}

/**
 * Every plausible plaintext a span's content could yield to a model that
 * decodes an obfuscation or folds homoglyphs. Used only to prove that a
 * plaintext destination seen in a call actually originated in untrusted data.
 */
function spanMatchForms(value: string): string[] {
  const forms = new Set<string>([value, foldConfusables(stripInvisible(value))]);
  for (const decoded of expandDecodedCandidates(value)) {
    forms.add(decoded);
    forms.add(foldConfusables(stripInvisible(decoded)));
  }
  const percent = tryPercentDecode(value);
  if (percent !== null) {
    forms.add(percent);
    forms.add(foldConfusables(stripInvisible(percent)));
  }
  return Array.from(forms);
}

/**
 * Every string leaf reachable from `value`: descends through objects and
 * arrays, and ALSO parses any string leaf that is itself a JSON object/array
 * and descends into it (arg-smuggling via a stringified or double-escaped
 * payload). Depth- and cycle-guarded. The raw string is always kept too, so a
 * destination that sits in the serialized text is matched even when the JSON
 * does not re-parse.
 */
function collectLeafStrings(value: unknown, depth = 0, seen: Set<object> = new Set()): string[] {
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
          out.push(...collectLeafStrings(parsed, depth + 1, seen));
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
    if (seen.has(value as object)) {
      return [];
    }
    seen.add(value as object);
    const children = Array.isArray(value) ? value : Object.values(value as Record<string, unknown>);
    return children.flatMap((child) => collectLeafStrings(child, depth + 1, seen));
  }
  return [];
}

function hostOf(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

/** Extract every email address and URL host present in a set of raw strings,
 * checking each string in all of its decoded/folded surface forms. */
function extractFromStrings(strings: string[]): Destinations {
  const dest = emptyDestinations();
  for (const raw of strings) {
    for (const form of extractionForms(raw)) {
      for (const match of form.matchAll(EMAIL_PATTERN)) {
        dest.emails.add(match[0].toLowerCase());
      }
      for (const match of form.matchAll(URL_PATTERN)) {
        const host = hostOf(match[0]);
        if (host) {
          dest.hosts.add(host);
        }
      }
    }
  }
  return dest;
}

/** Every destination a downstream tool would consume from a call's arguments. */
export function extractCallDestinations(args: unknown): Destinations {
  return extractFromStrings(collectLeafStrings(args));
}

/** Destinations the user explicitly named in their own (actionable) session
 * spans — the authorized set. Derived from provenance, never from the call. */
export function extractUserDestinations(spans: Span[]): Destinations {
  const userStrings = spans
    .filter((span) => span.origin === 'user-session' && span.trust === 'actionable')
    .map((span) => span.content);
  return extractFromStrings(userStrings);
}

/** True if `value` appears (in any decoded/folded surface form) inside any span
 * of the given trust. Used to prove a model-composed destination actually came
 * from untrusted (inert) data. */
function destinationTracesToTrust(value: string, spans: Span[], trust: Span['trust']): boolean {
  const target = value.toLowerCase();
  for (const span of spans) {
    if (span.trust !== trust) {
      continue;
    }
    for (const form of spanMatchForms(span.content)) {
      if (form.toLowerCase().includes(target)) {
        return true;
      }
    }
  }
  return false;
}

// Messaging / send intent in the user's own words. Used only to admit the
// benign "email my manager" delegation shape (a single model-resolved
// recipient the user asked to contact but did not spell out as an address).
const SEND_INTENT_PATTERN =
  /\b(?:e-?mail|send|forward|cc|bcc|notify|message|reply|share|distribute|inform|contact|post|upload|publish)\b|\bloop\s+in\b|\blet\s+[\w\s]{1,20}?\bknow\b/i;

// An address hint in untrusted text: a literal `@`, a spelled-out obfuscation
// (`x [at] y [dot] z`, `x at y dot z`), or a URL. Its presence means the inert
// span could itself be supplying a destination — so the benign-delegation
// allowance must NOT apply.
const ADDRESS_HINT_PATTERN =
  /@|\[\s*at\s*\]|\(\s*at\s*\)|\bat\b[^\n]{0,15}\bdot\b|https?:\/\//i;

function userSessionText(spans: Span[]): string {
  return spans
    .filter((span) => span.origin === 'user-session' && span.trust === 'actionable')
    .map((span) => span.content)
    .join('\n');
}

function userExpressedSendIntent(spans: Span[]): boolean {
  return SEND_INTENT_PATTERN.test(userSessionText(spans));
}

/**
 * True when no inert (untrusted) span in context looks like it could itself be
 * instructing a send or supplying a destination. The benign-delegation
 * allowance is only safe over a clean inert context; if untrusted data carries
 * a send instruction or an address hint, a model may have followed the
 * injection, so the allowance is withheld and the call falls through to the
 * generic fail-closed gates.
 */
function inertContextIsClean(spans: Span[]): boolean {
  for (const span of spans) {
    if (span.trust !== 'inert') {
      continue;
    }
    for (const form of spanMatchForms(span.content)) {
      if (SEND_INTENT_PATTERN.test(form) || ADDRESS_HINT_PATTERN.test(form)) {
        return false;
      }
    }
  }
  return true;
}

export type EgressDecision = 'block' | 'authorized' | 'not-applicable';

export interface EgressAuthorizationResult {
  decision: EgressDecision;
  reason: string;
  /** Destinations present in the call but not justified by the user session. */
  unauthorized: string[];
}

/**
 * Per-destination-kind authorization. Given the destinations of one kind
 * (email or host) the call carries and the ones the user authorized, decide
 * whether the call may proceed.
 *
 * Three outcomes:
 *  - 'authorized'     : every destination is one the user named, OR the call
 *                       is the single benign-delegation shape (see below).
 *  - 'block'          : the user named specific destinations of this kind and
 *                       the call carries at least one MORE — the extra one is
 *                       an off-intent/exfiltration target. This is the case the
 *                       generic provenance gates cannot see (the authorized
 *                       recipient masks the smuggled one), so egress must block
 *                       it outright.
 *  - 'not-applicable' : cannot positively authorize, but not a clear smuggle
 *                       either (a lone synthesized recipient with no user-named
 *                       set). Defer to the generic fail-closed gates, which
 *                       already block a sensitive action lacking user intent.
 *
 * Benign delegation (the "email my manager" case) requires ALL of: the user
 * named no destination of this kind, the call has exactly one, the user
 * expressed intent to perform the action, the inert context is clean of any
 * send instruction or address hint, and the lone destination does not trace to
 * an untrusted span. An attacker cannot satisfy it: a smuggled destination
 * arrives either beside a user-named one (blocked) or out of untrusted content
 * (which makes the inert context unclean / trips the trace check).
 */
function evaluateKind(
  kind: 'email' | 'host',
  callSet: Set<string>,
  userSet: Set<string>,
  spans: Span[]
): EgressAuthorizationResult {
  if (callSet.size === 0) {
    return { decision: 'not-applicable', reason: '', unauthorized: [] };
  }

  const unauthorized = [...callSet].filter((value) => !userSet.has(value));
  if (unauthorized.length === 0) {
    return {
      decision: 'authorized',
      reason: `All ${kind} destinations are authorized by the user session.`,
      unauthorized: []
    };
  }

  if (userSet.size > 0) {
    // The user named specific destinations; anything beyond them is smuggled.
    return {
      decision: 'block',
      reason: `Blocked because the call carries ${kind} destination(s) the user never authorized: ${unauthorized.join(', ')}.`,
      unauthorized
    };
  }

  const isBenignDelegation =
    callSet.size === 1 &&
    userExpressedSendIntent(spans) &&
    inertContextIsClean(spans) &&
    !destinationTracesToTrust(unauthorized[0]!, spans, 'inert');

  if (isBenignDelegation) {
    return {
      decision: 'authorized',
      reason: `Single ${kind} destination resolved from an explicit user request over a clean untrusted context.`,
      unauthorized: []
    };
  }

  // A lone, unauthorized destination with no user-named set: not a provable
  // smuggle, but not authorized either. Defer to the generic gates.
  return { decision: 'not-applicable', reason: '', unauthorized: [] };
}

/**
 * Authorize the egress destinations of a sensitive tool call against the user
 * session. Returns:
 *   - 'block'          : at least one destination is unauthorized (exfiltration).
 *   - 'authorized'     : every destination is justified by the user.
 *   - 'not-applicable' : the call carries no email/host destination, so this
 *                        check has nothing to say (caller falls back to the
 *                        generic provenance/user-session gates).
 */
export function egressAuthorizationCheck(args: unknown, spans: Span[]): EgressAuthorizationResult {
  const call = extractCallDestinations(args);
  const user = extractUserDestinations(spans);

  const emailResult = evaluateKind('email', call.emails, user.emails, spans);
  if (emailResult.decision === 'block') {
    return emailResult;
  }
  const hostResult = evaluateKind('host', call.hosts, user.hosts, spans);
  if (hostResult.decision === 'block') {
    return hostResult;
  }

  if (emailResult.decision === 'authorized' || hostResult.decision === 'authorized') {
    const reasons = [emailResult, hostResult]
      .filter((result) => result.decision === 'authorized')
      .map((result) => result.reason);
    return { decision: 'authorized', reason: reasons.join(' '), unauthorized: [] };
  }

  return { decision: 'not-applicable', reason: '', unauthorized: [] };
}
