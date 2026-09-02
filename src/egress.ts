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
  /** URL origins (scheme://host[:port], default ports normalized away), NOT
   * bare hostnames — network destinations are authorized at origin granularity. */
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

// A network destination is authorized at ORIGIN granularity — scheme + host +
// port — not bare hostname (audit follow-up). Binding the scheme and port stops
// an authorized `https://trusted.example/status` from also authorizing
// `https://trusted.example:444/admin` or an `http://` downgrade. The URL path
// is intentionally NOT bound: authorizing an origin authorizes all paths on it
// (a status/webhook host is authorized as a host), a decision recorded in
// docs/threat-model.md. `URL.origin` normalizes default ports away, so
// `:443`/`:80` compare equal to the bare form.
function originOf(url: string): string | null {
  try {
    const origin = new URL(url).origin;
    return origin && origin !== 'null' ? origin.toLowerCase() : null;
  } catch {
    return null;
  }
}

/** Extract every email address and URL origin present in a set of raw strings,
 * checking each string in all of its decoded/folded surface forms. */
function extractFromStrings(strings: string[]): Destinations {
  const dest = emptyDestinations();
  for (const raw of strings) {
    for (const form of extractionForms(raw)) {
      for (const match of form.matchAll(EMAIL_PATTERN)) {
        dest.emails.add(match[0].toLowerCase());
      }
      for (const match of form.matchAll(URL_PATTERN)) {
        const origin = originOf(match[0]);
        if (origin) {
          dest.hosts.add(origin);
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

interface TypedDestination {
  kind: 'email' | 'host';
  value: string;
}

function typedDestinations(dest: Destinations): TypedDestination[] {
  return [
    ...[...dest.emails].map((value): TypedDestination => ({ kind: 'email', value })),
    ...[...dest.hosts].map((value): TypedDestination => ({ kind: 'host', value }))
  ];
}

/**
 * Authorize the egress destinations of a sensitive tool call against the user
 * session, evaluating EVERY destination across EVERY kind together (never one
 * kind at a time). A call is authorized only when every extracted destination
 * — email or host, at any depth — is one the user positively authorized; a
 * single authorized destination of one kind can never license an unauthorized
 * destination of another kind. This closes the cross-kind masking bypass where
 * an authorized recipient rode alongside an unauthorized callback host.
 *
 * Returns:
 *   - 'block'          : at least one destination is unauthorized AND the call
 *                        is not the benign single-delegation shape — either the
 *                        user named some destination (so any extra is smuggled)
 *                        or the call carries more than one destination (so it
 *                        cannot be a lone delegation). Fail-closed.
 *   - 'authorized'     : every destination is justified — all user-named, or the
 *                        whole call is the single benign-delegation shape.
 *   - 'not-applicable' : the call carries no destination, OR a single
 *                        unauthorized destination with no user-named set that is
 *                        not delegation-eligible. Defer to the generic
 *                        provenance/user-session gates (which already block a
 *                        synthesized-recipient send, with a precise reason).
 *
 * Benign delegation (the "email my manager" case) requires ALL of: the user
 * named no destination of any kind, the call carries exactly one destination
 * total, the user expressed intent to perform the action, the inert context is
 * clean of any send instruction or address hint, and that lone destination does
 * not trace to an untrusted span. An attacker cannot satisfy it: a smuggled
 * destination arrives either beside a user-named one (blocked), as a second
 * destination (blocked), or out of untrusted content (unclean inert / trips the
 * trace check).
 */
export function egressAuthorizationCheck(args: unknown, spans: Span[]): EgressAuthorizationResult {
  const call = extractCallDestinations(args);
  const user = extractUserDestinations(spans);

  const dests = typedDestinations(call);
  if (dests.length === 0) {
    return { decision: 'not-applicable', reason: '', unauthorized: [] };
  }

  const userNamedAny = user.emails.size + user.hosts.size > 0;
  const isAuthorized = (d: TypedDestination): boolean =>
    (d.kind === 'email' ? user.emails : user.hosts).has(d.value);
  const unauthorized = dests.filter((d) => !isAuthorized(d));

  if (unauthorized.length === 0) {
    return {
      decision: 'authorized',
      reason: 'All egress destinations are authorized by the user session.',
      unauthorized: []
    };
  }

  const isBenignDelegation =
    dests.length === 1 &&
    !userNamedAny &&
    userExpressedSendIntent(spans) &&
    inertContextIsClean(spans) &&
    !destinationTracesToTrust(unauthorized[0]!.value, spans, 'inert');

  if (isBenignDelegation) {
    return {
      decision: 'authorized',
      reason: 'Single egress destination resolved from an explicit user request over a clean untrusted context.',
      unauthorized: []
    };
  }

  // Smuggle: the user named a destination (so any unauthorized one is an
  // extra), or the call carries more than one destination (so it cannot be a
  // lone delegation and at least one is unauthorized). Block outright.
  if (userNamedAny || dests.length > 1) {
    return {
      decision: 'block',
      reason: `Blocked because the call carries egress destination(s) the user never authorized: ${unauthorized
        .map((d) => d.value)
        .join(', ')}.`,
      unauthorized: unauthorized.map((d) => d.value)
    };
  }

  // A single unauthorized destination, user named nothing, not delegation-
  // eligible: not a provable smuggle. Defer to the generic fail-closed gates
  // so they can block it with their specific provenance/intent reason.
  return { decision: 'not-applicable', reason: '', unauthorized: unauthorized.map((d) => d.value) };
}
