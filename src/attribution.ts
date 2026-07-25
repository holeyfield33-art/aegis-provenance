import type { Span } from './types.js';
import { candidateRepresentations, normalizeMatchText } from './normalize.js';

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

function extractStrings(value: unknown): string[] {
  if (value === null || value === undefined) {
    return [];
  }

  if (typeof value === 'string') {
    return [value];
  }

  if (typeof value === 'number' || typeof value === 'boolean') {
    return [String(value)];
  }

  if (Array.isArray(value)) {
    return value.flatMap((item) => extractStrings(item));
  }

  if (typeof value === 'object') {
    return Object.values(value).flatMap((item) => extractStrings(item));
  }

  return [];
}

export function argumentProvenanceMatch(args: unknown, spans: Span[]): ProvenanceMatchResult {
  const argValues = extractStrings(args).map((value) => normalizeMatchText(value)).filter(Boolean);
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

export function canaryDetection(output: string, canaryMap: Record<string, string>): CanaryDetectionResult {
  const triggeredSpanIds: string[] = [];
  const payload = normalizeText(output);

  for (const [spanId, canary] of Object.entries(canaryMap)) {
    if (payload.includes(normalizeText(canary))) {
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

  const argValues = extractStrings(args)
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
 */
export function contentSensitivityCheck(args: unknown): ContentSensitivityResult {
  const reasons = new Set<string>();

  for (const raw of extractStrings(args)) {
    if (SECRET_KEY_NAME_PATTERN.test(raw)) {
      reasons.add('argument references an environment-variable-shaped secret name');
    }
    if (SECRET_VALUE_PATTERN.test(raw)) {
      reasons.add('argument contains a credential-shaped token');
    }
    if (CREDENTIAL_FILE_PATTERN.test(raw)) {
      reasons.add('argument references a credential file path');
    }
    if (SECRET_REQUEST_PATTERN.test(raw)) {
      reasons.add('argument requests secret or credential material');
    }
    if (PATH_TRAVERSAL_PATTERN.test(raw)) {
      reasons.add('argument contains a path traversal sequence');
    }
    if (IDENTITY_OVERRIDE_PATTERN.test(raw)) {
      reasons.add('argument attempts to redefine acting identity or override system framing');
    }
  }

  return { sensitive: reasons.size > 0, reasons: Array.from(reasons) };
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
  const rule = sensitivityTable.rules.find((ruleItem) => ruleItem.actionPattern.test(lowerName));
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
  const provenanceMatch = argumentProvenanceMatch(args, spans);
  const argsCanary = canaryDetection(JSON.stringify(args ?? null), canaryMap);
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
