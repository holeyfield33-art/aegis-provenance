import type { Span } from './types.js';
import { AegisAttributionError } from './types.js';
import { candidateRepresentations, candidateContentRepresentations, normalizeMatchText } from './normalize.js';
import { egressAuthorizationCheck } from './egress.js';
import { resolveCanonicalTool } from './tool-contracts.js';
import { collectLeafStrings, hasCircularReference } from './traversal.js';

export interface ProvenanceMatchResult {
  inertOnly: boolean;
  actionablePresent: boolean;
  matchedSpanIds: string[];
  /**
   * True if at least one *individual* argument value's matches are
   * exclusively inert spans (no actionable span also matched that same
   * value). Unlike `inertOnly`/`actionablePresent` — which OR matches
   * together across every argument value — this is evaluated per value, so
   * an unrelated benign field (e.g. a "subject" that happens to share a
   * common word with the user's message, and therefore matches an
   * actionable span) can't mask a different field whose content is sourced
   * only from an inert span. Callers deciding whether to block a sensitive
   * action should use this field, not the aggregate ones.
   */
  anyValueInertOnly: boolean;
}

export interface CanaryDetectionResult {
  triggered: boolean;
  triggeredSpanIds: string[];
}

export interface SensitivityRule {
  actionPattern: RegExp;
  sensitive: boolean;
  requiresUserSession: boolean;
  allowInert: boolean;
}

export interface SensitivityTable {
  rules: SensitivityRule[];
}

export interface AttributionSignals {
  provenanceMatch: ProvenanceMatchResult;
  canary: CanaryDetectionResult;
  sensitiveAction: boolean;
  requiresUserSession: boolean;
  allowInert: boolean;
  hasUserSessionIntent: boolean;
}

export interface AttributionDecision {
  verdict: 'allow' | 'block' | 'flag';
  reason: string;
  attribution: ProvenanceMatchResult;
  canary: CanaryDetectionResult;
  sensitiveAction: boolean;
}

const defaultSensitivityTable: SensitivityTable = {
  rules: [
    { actionPattern: /^send_/, sensitive: true, requiresUserSession: true, allowInert: false },
    { actionPattern: /^http_post$/, sensitive: true, requiresUserSession: true, allowInert: false },
    { actionPattern: /^delete_/, sensitive: true, requiresUserSession: true, allowInert: false },
    { actionPattern: /^transfer_/, sensitive: true, requiresUserSession: true, allowInert: false },
    { actionPattern: /permission/, sensitive: true, requiresUserSession: true, allowInert: false },
    { actionPattern: /^search$/, sensitive: false, requiresUserSession: false, allowInert: true },
    { actionPattern: /^read_file$/, sensitive: false, requiresUserSession: false, allowInert: true }
  ]
};

function normalizeText(value: string): string {
  return value.replace(/\s+/g, ' ').trim().toLowerCase();
}

// Circular-reference detection and leaf-string extraction now live in
// src/traversal.ts, shared with egress.ts (#41) — see that module's header
// for why the two traversals had drifted (JSON-in-string parsing and a depth
// budget existed only on the egress side) and why this needed to be a single
// implementation.

export function argumentProvenanceMatch(args: unknown, spans: Span[]): ProvenanceMatchResult {
  const argValues = collectLeafStrings(args).map((value) => normalizeMatchText(value)).filter(Boolean);
  // A model that decodes an obfuscated span (base64/hex/rot13) or folds
  // homoglyphs when repeating it produces plaintext that no longer appears
  // byte-for-byte in the span. Matching against every plausible decoded/
  // folded representation of each span's content — not just its literal
  // text — recovers that link. This is a superset of literal matching (the
  // literal normalized text is always included as one candidate), so it
  // only ever finds matches the old check would have missed.
  const spanCandidates = new Map<string, string[]>();
  for (const span of spans) {
    spanCandidates.set(span.id, candidateRepresentations(span.content));
  }

  const matchedSpanIds = new Set<string>();
  let actionablePresent = false;
  let matchedAny = false;
  let onlyInert = true;
  let anyValueInertOnly = false;

  for (const value of argValues) {
    const matches = spans.filter((span) => (spanCandidates.get(span.id) ?? []).some((candidate) => candidate.includes(value)));
    if (matches.length === 0) {
      continue;
    }

    matchedAny = true;
    let valueActionable = false;
    let valueInert = false;
    for (const span of matches) {
      matchedSpanIds.add(span.id);
      if (span.trust === 'actionable') {
        actionablePresent = true;
        valueActionable = true;
      }
      if (span.trust !== 'inert') {
        onlyInert = false;
      } else {
        valueInert = true;
      }
    }
    if (valueInert && !valueActionable) {
      anyValueInertOnly = true;
    }
  }

  return {
    inertOnly: matchedAny && onlyInert,
    actionablePresent,
    matchedSpanIds: Array.from(matchedSpanIds),
    anyValueInertOnly
  };
}

// #40: this used to normalize with the weak local `normalizeText` (whitespace
// collapse + lowercase only), while the provenance-matching pipeline used the
// stronger `normalizeMatchText` (invisible-character stripping + NFKC/
// homoglyph folding). Since the canary value is rendered directly into the
// untrusted span's own framing (`Canary: ${canary}` in assembly.ts), a model
// that has been instructed by injected content to reproduce "internal
// markers" with e.g. a zero-width space spliced in, or a Cyrillic look-alike
// substituted for a Latin letter, could reflect an altered canary that the
// weak normalizer would never match against the clean stored value —
// silently defeating hidden-instruction-use detection. Both sides of the
// comparison now go through the same canonical security normalizer.
export function canaryDetection(output: string, canaryMap: Record<string, string>): CanaryDetectionResult {
  const triggeredSpanIds: string[] = [];
  const payload = normalizeMatchText(output);

  for (const [spanId, canary] of Object.entries(canaryMap)) {
    if (payload.includes(normalizeMatchText(canary))) {
      triggeredSpanIds.push(spanId);
    }
  }

  return {
    triggered: triggeredSpanIds.length > 0,
    triggeredSpanIds
  };
}

/**
 * A user-session span expresses intent for an action only if it actually
 * references it: an explicit `intent:<tool_name>` marker, one of the
 * argument values appearing in the user's own words, or — only when no
 * untrusted/inert content is present anywhere in context — bare token
 * overlap with the action name. Mere existence of a user-session span is
 * not intent — the harness always injects one, so an existence check can
 * never fire.
 *
 * The bare-token-overlap fallback is intentionally weak (it exists to keep
 * low-friction phrasing like "email the report to my manager" working when
 * a model resolves the recipient from context). That weakness becomes a
 * bypass the moment untrusted content is also in the span set: an attacker
 * doesn't need the user to reference their target at all, just needs a
 * generic word like "email" to appear anywhere in the user's message by
 * coincidence, while the actual (obfuscated or paraphrased) exfil target
 * comes from the untrusted span and never has to match anything literally.
 * So once any inert (untrusted) span exists in context, we require the
 * stronger evidence — an explicit marker or genuine argument-value overlap
 * — instead of falling back to token overlap.
 */
export function userSessionIntentMatch(actionName: string, args: unknown, spans: Span[]): boolean {
  const userText = normalizeText(
    spans
      .filter((span) => span.origin === 'user-session' && span.trust === 'actionable')
      .map((span) => span.content)
      .join('\n')
  );
  if (!userText) {
    return false;
  }

  const lowerName = actionName.toLowerCase();
  if (lowerName && userText.includes(`intent:${lowerName}`)) {
    return true;
  }

  const argValues = collectLeafStrings(args)
    .map((value) => normalizeText(value))
    .filter((value) => value.length >= 3);
  if (argValues.some((value) => userText.includes(value))) {
    return true;
  }

  const hasUntrustedContent = spans.some((span) => span.trust === 'inert');
  if (hasUntrustedContent) {
    return false;
  }

  const actionTokens = lowerName.split(/[^a-z0-9]+/).filter((token) => token.length >= 3);
  return actionTokens.some((token) => userText.includes(token));
}

// Content-based sensitivity: classifies a tool call as sensitive from what
// its arguments actually contain, independent of the tool's name. The
// name-pattern table above only recognizes a fixed set of verbs in the tool
// name itself, so a call to e.g. `search` or `read_file` carrying
// exfiltration-shaped arguments — a secret name, a credential file path, a
// path-traversal sequence, or identity-override text — was never routed
// through the provenance/user-intent checks below at all. Any of these
// patterns matching an argument value makes the action sensitive regardless
// of its name, so it reaches the same checks a named-sensitive tool would.

// Shouting-case environment-variable-style secret names, e.g.
// AEGIS_EVAL_API_KEY, AWS_SECRET_ACCESS_KEY, DB_PASSWORD. Case-sensitive by
// design: ordinary prose essentially never contains multi-segment, all-caps,
// underscore-joined tokens, so this carries very low false-positive risk
// without needing an accompanying verb.
const SECRET_KEY_NAME_PATTERN = /\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*_(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIALS?)\b/;

// Known credential-token shapes (common provider API-key prefixes, AWS
// access key IDs).
const SECRET_VALUE_PATTERN =
  /\bsk-[A-Za-z0-9]{10,}\b|\bhf_[A-Za-z0-9]{10,}\b|\bgh[pousr]_[A-Za-z0-9]{16,}\b|\bAKIA[0-9A-Z]{16}\b|\bxox[baprs]-[A-Za-z0-9-]{10,}\b/;

// Credential/secret file paths.
const CREDENTIAL_FILE_PATTERN =
  /(?:^|[\s"'`(/\\])(\.env(?:\.\w+)?|id_rsa(?:\.pub)?|id_ed25519(?:\.pub)?|\.pem|\.ppk|credentials\.json|\.aws[/\\]credentials|\.npmrc|\.git-credentials|\.pgpass|\.ssh[/\\][\w.-]+|etc[/\\]shadow|etc[/\\]passwd)\b/i;

// Imperative requests for secret/credential material, independent of any
// specific token shape (e.g. "reveal the api key").
const SECRET_REQUEST_PATTERN =
  /\b(?:reveal|dump|print|show|display|return|tell me|give me|exfiltrate|leak)\b[^\n]{0,40}\b(?:api[- ]?key|access token|secret key|private key|password|credentials?|env(?:ironment)?\s+variables?)\b/i;

// Path traversal sequences and known-sensitive absolute paths.
const PATH_TRAVERSAL_PATTERN =
  /\.\.[/\\]|[/\\]etc[/\\](?:passwd|shadow)\b|[/\\]proc[/\\]self[/\\]environ\b|[A-Za-z]:[\\/]+Windows[\\/]+System32/i;

// Reflected content that redefines the acting identity or overrides system
// framing (identity confusion / reflection-context override). "ignore" /
// "disregard" use a bounded gap rather than an enumerated qualifier list so
// multi-qualifier phrasing ("ignore all previous instructions") still
// matches instead of only single-qualifier variants.
const IDENTITY_OVERRIDE_PATTERN =
  /\byou are now\b|\bact(?:ing)? as (?:the )?system\b|\bsystem override\b|\bignore\b[^\n]{0,20}\binstructions\b|\bdisregard\b[^\n]{0,20}\binstructions\b|\bnew system prompt\b|\btreat this (?:message|content) as (?:the )?system\b|\brole\s*[:=]\s*system\b/i;

export interface ContentSensitivityResult {
  sensitive: boolean;
  reasons: string[];
}

/**
 * Scans tool-call argument values for content that is inherently sensitive
 * regardless of which tool is being called: secret material, path
 * traversal, or identity/system-framing override attempts. This is the
 * content-based counterpart to the name-based table — it is what lets
 * `sensitiveActionPolicy` catch a `search` or `read_file` call that carries
 * exfiltration-shaped arguments.
 *
 * Each argument value is matched not only literally but across its
 * case-preserving decoded/folded representations (base64/hex/rot13,
 * homoglyph-folded, invisible-stripped). Without this, wrapping any of these
 * triggers in base64 or hex — the same evasion the provenance side already
 * handles — left this content layer completely blind: an encoded secret name
 * or credential path was a clean `allow`. `candidateContentRepresentations`
 * preserves case so the case-sensitive patterns (all-caps secret names, AWS
 * AKIA ids) still fire, and includes the raw text, so this only ever adds
 * matches the literal-only check would have missed.
 */
export function contentSensitivityCheck(args: unknown): ContentSensitivityResult {
  const reasons = new Set<string>();

  for (const value of collectLeafStrings(args)) {
    for (const rep of candidateContentRepresentations(value)) {
      if (SECRET_KEY_NAME_PATTERN.test(rep)) {
        reasons.add('argument references an environment-variable-shaped secret name');
      }
      if (SECRET_VALUE_PATTERN.test(rep)) {
        reasons.add('argument contains a credential-shaped token');
      }
      if (CREDENTIAL_FILE_PATTERN.test(rep)) {
        reasons.add('argument references a credential file path');
      }
      if (SECRET_REQUEST_PATTERN.test(rep)) {
        reasons.add('argument requests secret or credential material');
      }
      if (PATH_TRAVERSAL_PATTERN.test(rep)) {
        reasons.add('argument contains a path traversal sequence');
      }
      if (IDENTITY_OVERRIDE_PATTERN.test(rep)) {
        reasons.add('argument attempts to redefine acting identity or override system framing');
      }
    }
  }

  return { sensitive: reasons.size > 0, reasons: Array.from(reasons) };
}

// Correction-as-escalation detection -----------------------------------
//
// A model that (a) asserts a specific technical correction about what a
// named tool/system actually is or does, and then (b) supplies
// offensive-tooling artifacts later in the same response, has demonstrated
// it understood the request more precisely than its surface framing implied
// — and that improved understanding never became a reason to withhold.
// Neither signal alone is a problem: technical corrections are normal
// helpful behavior, and naming a security tool is normal in a security
// context. It's the co-occurrence — correction followed by offensive
// artifact in the same free-text response — that is the signature of a
// request that primed the model with a plausible misconception so its own
// accurate correction would supply what the framing was actually pointing
// at. This only inspects free-text output; tool-call args are already
// covered by contentSensitivityCheck above.
const CORRECTION_MARKER_PATTERN =
  /\b(?:is not|isn't|actually is|is actually|to be clear,? (?:it|this|that)|is just|is only)\b[^\n]{0,80}\b(?:harness|utility|payload|launcher|tool|target|endpoint|flag|library|script)\b/i;

const OFFENSIVE_ARTIFACT_PATTERN =
  /\b(?:metasploit|meterpreter|cobalt\s*strike|sqlmap|mimikatz|empire\s+c2)\b|\bFROM\s+kali(?:linux)?\/kali\b|\bautonomous\b[^\n]{0,60}\b(?:recon|exploit|tool)\b[^\n]{0,40}\bloop\b/i;

export interface TextEscalationResult {
  escalation: boolean;
  reasons: string[];
}

/**
 * Scans a model's free-text response for the correction-as-escalation
 * pattern: a declarative technical correction about a tool/system's scope,
 * co-occurring with offensive-tooling content. See block comment above for
 * the reasoning behind why this pattern, specifically, warrants a check
 * independent of the name/content-based tool-call checks.
 */
export function textEscalationCheck(text: string): TextEscalationResult {
  if (!text) {
    return { escalation: false, reasons: [] };
  }

  const correctionMatch = CORRECTION_MARKER_PATTERN.exec(text);
  if (!correctionMatch) {
    return { escalation: false, reasons: [] };
  }

  // The signature is ordered: the correction must come first, with the
  // offensive artifact following it. Scan every artifact occurrence (a
  // single exec() would only see the first, which may precede the
  // correction) and require at least one at or after the correction.
  const artifactScan = new RegExp(OFFENSIVE_ARTIFACT_PATTERN.source, 'gi');
  const artifactAfterCorrection = [...text.matchAll(artifactScan)].some(
    (match) => match.index >= correctionMatch.index
  );
  if (!artifactAfterCorrection) {
    return { escalation: false, reasons: [] };
  }

  return {
    escalation: true,
    reasons: [
      'response contains a technical correction about tool/system scope',
      'offensive-tooling artifact appears after the correction (correction-as-escalation pattern)'
    ]
  };
}

export function sensitiveActionPolicy(
  actionName: string,
  args: unknown,
  spans: Span[],
  sensitivityTable: SensitivityTable = defaultSensitivityTable
): {
  sensitiveAction: boolean;
  requiresUserSession: boolean;
  allowInert: boolean;
  hasUserSessionIntent: boolean;
  contentSensitivity: ContentSensitivityResult;
} {
  const lowerName = actionName.toLowerCase();
  // Match sensitivity rules against BOTH the raw name and the canonical tool the
  // name resolves to, so a documented alias (`send_http`, `http_request`, `rm`,
  // `mail`) is classified as the sensitive tool it reaches rather than slipping
  // past a name-pattern that only knows the canonical spelling. Without this a
  // direct decideAttribution caller could route a sensitive egress alias around
  // the sensitivity gate (and thus around egress destination authorization).
  const canonical = resolveCanonicalTool(actionName);
  const rule = sensitivityTable.rules.find(
    (ruleItem) => ruleItem.actionPattern.test(lowerName) || (canonical !== null && ruleItem.actionPattern.test(canonical))
  );
  const hasUserSessionIntent = userSessionIntentMatch(actionName, args, spans);
  const contentSensitivity = contentSensitivityCheck(args);

  // Content-based sensitivity overrides an absent or non-sensitive
  // name-based rule: whatever the tool is called, arguments that look like
  // secret exfiltration, path traversal, or an identity/framing override
  // must clear the same user-intent bar a named-sensitive tool would.
  if (contentSensitivity.sensitive) {
    return {
      sensitiveAction: true,
      requiresUserSession: true,
      allowInert: false,
      hasUserSessionIntent,
      contentSensitivity
    };
  }

  if (!rule) {
    return {
      sensitiveAction: false,
      requiresUserSession: false,
      allowInert: false,
      hasUserSessionIntent,
      contentSensitivity
    };
  }

  return {
    sensitiveAction: rule.sensitive,
    requiresUserSession: rule.requiresUserSession,
    allowInert: rule.allowInert,
    hasUserSessionIntent,
    contentSensitivity
  };
}

export function decideAttribution(
  actionName: string,
  args: unknown,
  canaryMap: Record<string, string>,
  spans: Span[],
  sensitivityTable: SensitivityTable = defaultSensitivityTable,
  modelText?: string
): {
  verdict: 'allow' | 'block' | 'flag';
  reason: string;
  attribution: ProvenanceMatchResult;
  canary: CanaryDetectionResult;
  sensitiveAction: boolean;
} {
  if (hasCircularReference(args)) {
    throw new AegisAttributionError('Model returned tool_args containing a circular reference, which cannot be analyzed.');
  }

  const provenanceMatch = argumentProvenanceMatch(args, spans);
  // hasCircularReference's cycle check is depth-guarded (TRAVERSAL_MAX_DEPTH,
  // traversal.ts) for the same DoS reason collectLeafStrings is: a real cycle
  // is always caught within a handful of steps (bounded by the number of
  // distinct objects in the cycle), which is what makes capping depth safe
  // for THAT check. But a pathological "long acyclic chain that only THEN
  // closes into a cycle" — the back-edge sitting deeper than the depth
  // budget — is missed by the capped walk, while Node's native
  // JSON.stringify still detects it (it isn't depth-limited) and throws a
  // TypeError, not a RangeError. A prior version of this fix only caught
  // RangeError here, which still let that TypeError escape uncaught —
  // caught by Copilot review on PR #51. Catching broadly at this single,
  // narrow call site (rather than guessing at error subtypes) converts any
  // serialization failure into the same typed, fail-closed error the
  // circular-reference guard above already uses.
  let argsSerialized: string;
  try {
    argsSerialized = JSON.stringify(args ?? null);
  } catch (cause) {
    throw new AegisAttributionError(
      `Model returned tool_args that could not be serialized for canary detection (too deeply nested, or a circular reference beyond the traversal's cycle-detection budget): ${cause instanceof Error ? cause.message : String(cause)}`
    );
  }
  const argsCanary = canaryDetection(argsSerialized, canaryMap);
  const textCanary = canaryDetection(modelText ?? '', canaryMap);
  const canary: CanaryDetectionResult = {
    triggered: argsCanary.triggered || textCanary.triggered,
    triggeredSpanIds: Array.from(new Set([...argsCanary.triggeredSpanIds, ...textCanary.triggeredSpanIds]))
  };
  const policy = sensitiveActionPolicy(actionName, args, spans, sensitivityTable);

  if (argsCanary.triggered) {
    if (policy.sensitiveAction) {
      return {
        verdict: 'block',
        reason: `Blocked because canary content from inert span(s) [${argsCanary.triggeredSpanIds.join(', ')}] was reflected in tool arguments.`,
        attribution: provenanceMatch,
        canary,
        sensitiveAction: policy.sensitiveAction
      };
    }

    return {
      verdict: 'flag',
      reason: `Flagged because canary content from inert span(s) [${argsCanary.triggeredSpanIds.join(', ')}] was reflected in tool arguments.`,
      attribution: provenanceMatch,
      canary,
      sensitiveAction: policy.sensitiveAction
    };
  }

  if (policy.sensitiveAction) {
    const contentNote = policy.contentSensitivity.sensitive
      ? ` (${policy.contentSensitivity.reasons.join('; ')})`
      : '';

    // Unified sensitive-tool / egress-contract classification (#39): a
    // sensitive action must either resolve to a tool tool-contracts.ts
    // actually knows (so egress destination authorization below is a real
    // check, even when this particular call carries no destination) or be
    // rejected HERE, explicitly and fail-closed. Without this, a tool name
    // that satisfies the sensitivity table's name-pattern rules (e.g.
    // `/^send_/`) but isn't one of the exact aliases in tool-contracts.ts's
    // TOOL_ALIASES resolves to `egressContract === 'none'`, which
    // `egressAuthorizationCheck` cannot distinguish from "a recognized
    // non-egress tool" — it returns 'not-applicable' either way, silently
    // downgrading to the generic substring-only provenance/user-session
    // gates below. Those gates evaluate `hasUserSessionIntent` once for the
    // WHOLE call, so an authorized recipient anywhere in the arguments (e.g.
    // `to: "alice@corp.example"`, present verbatim in the user's own
    // message) satisfies intent for the ENTIRE call, including a sibling
    // `bcc` field the user never authorized — reopening exactly the
    // authorized-recipient-plus-hidden-BCC smuggle the structural egress
    // check exists to close. (Confirmed exploitable pre-fix: calling an
    // unregistered alias like `send_widgets` with
    // `{ to: "alice@corp.example", bcc: "attacker@evil.example" }` was
    // silently ALLOWED.)
    //
    // Canonical tools that are deliberately non-egress (`delete_file`,
    // `transfer_funds`, `set_permission`, `search`, `read_file`) are NOT
    // affected: they resolve here (tool-contracts.ts documents them, just
    // with an egress contract of `'none'` by design), so only a name Aegis
    // has genuinely never heard of — sensitive by the caller's own
    // sensitivity table, unclassified by the tool registry — takes this
    // path. Extending TOOL_ALIASES with more names does not remove this
    // check; it is the fail-closed backstop for whatever isn't registered.
    if (resolveCanonicalTool(actionName) === null) {
      return {
        verdict: 'block',
        reason:
          `Blocked because '${actionName}' is a sensitive action with no known destination/security contract in ` +
          `tool-contracts.ts${contentNote}. An unclassified sensitive tool can never be positively authorized on ` +
          `egress grounds; register it with an explicit contract before enabling it.`,
        attribution: provenanceMatch,
        canary,
        sensitiveAction: policy.sensitiveAction
      };
    }

    // Structural destination authorization (#27/#28/#29): every egress
    // destination the call carries — at any depth, inside JSON-in-string,
    // header-injected lines, CSV/array lists, or behind an encoding/homoglyph
    // — must be one the user actually authorized. This is what catches an
    // authorized-recipient-plus-hidden-BCC exfiltration that substring
    // provenance alone lets through.
    const egress = egressAuthorizationCheck(actionName, args, spans);
    if (egress.decision === 'block') {
      return {
        verdict: 'block',
        reason: `${egress.reason}${contentNote}`,
        attribution: provenanceMatch,
        canary,
        sensitiveAction: policy.sensitiveAction
      };
    }

    // When egress authorization has positively cleared every destination the
    // call transmits to (all user-named, or the single benign-delegation
    // shape), the destinations are justified and the generic inert/
    // user-session gates below — which cannot see structured recipients — are
    // skipped for this call. Otherwise fall back to them.
    if (egress.decision !== 'authorized') {
      if (provenanceMatch.anyValueInertOnly) {
        return {
          verdict: 'block',
          reason: `Blocked because tool arguments originate only from inert spans for a sensitive action${contentNote}.`,
          attribution: provenanceMatch,
          canary,
          sensitiveAction: policy.sensitiveAction
        };
      }

      if (policy.requiresUserSession && !policy.hasUserSessionIntent) {
        return {
          verdict: 'block',
          reason: `Blocked because a sensitive action requires user-session intent that references the action or its arguments${contentNote}.`,
          attribution: provenanceMatch,
          canary,
          sensitiveAction: policy.sensitiveAction
        };
      }
    }
  }

  // Correction-as-escalation: flag, don't block. This pattern has real
  // false-positive surface (legitimate security educators correct
  // misconceptions and cite offensive tools all the time), so a hard block
  // is too aggressive here — the receipt trail and human review are the
  // right first line, same posture as the canary-in-text case below.
  const textEscalation = textEscalationCheck(modelText ?? '');
  if (textEscalation.escalation) {
    return {
      verdict: 'flag',
      reason: `Flagged: ${textEscalation.reasons.join('; ')}.`,
      attribution: provenanceMatch,
      canary,
      sensitiveAction: policy.sensitiveAction
    };
  }

  // Canary in free-text output is read-only exfiltration evidence: advisory
  // flag, never block — the text itself executes nothing.
  if (textCanary.triggered) {
    return {
      verdict: 'flag',
      reason: `Flagged because canary content from inert span(s) [${textCanary.triggeredSpanIds.join(', ')}] was reflected in model text output.`,
      attribution: provenanceMatch,
      canary,
      sensitiveAction: policy.sensitiveAction
    };
  }

  return {
    verdict: 'allow',
    reason: 'Allowed by deterministic provenance checks.',
    attribution: provenanceMatch,
    canary,
    sensitiveAction: policy.sensitiveAction
  };
}
