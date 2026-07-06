import type { Span } from './types.js';

export interface ProvenanceMatchResult {
  inertOnly: boolean;
  actionablePresent: boolean;
  matchedSpanIds: string[];
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
  const argValues = extractStrings(args).map((value) => normalizeText(value)).filter(Boolean);
  const matchedSpanIds = new Set<string>();
  let actionablePresent = false;
  let matchedAny = false;
  let onlyInert = true;

  for (const value of argValues) {
    const matches = spans.filter((span) => normalizeText(span.content).includes(value));
    if (matches.length === 0) {
      continue;
    }

    matchedAny = true;
    for (const span of matches) {
      matchedSpanIds.add(span.id);
      if (span.trust === 'actionable') {
        actionablePresent = true;
      }
      if (span.trust !== 'inert') {
        onlyInert = false;
      }
    }
  }

  return {
    inertOnly: matchedAny && onlyInert,
    actionablePresent,
    matchedSpanIds: Array.from(matchedSpanIds)
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
 * references it: an explicit `intent:<tool_name>` marker, token overlap with
 * the action name, or one of the argument values appearing in the user's own
 * words. Mere existence of a user-session span is not intent — the harness
 * always injects one, so an existence check can never fire.
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

  const actionTokens = lowerName.split(/[^a-z0-9]+/).filter((token) => token.length >= 3);
  if (actionTokens.some((token) => userText.includes(token))) {
    return true;
  }

  const argValues = extractStrings(args)
    .map((value) => normalizeText(value))
    .filter((value) => value.length >= 3);
  return argValues.some((value) => userText.includes(value));
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
} {
  const lowerName = actionName.toLowerCase();
  const rule = sensitivityTable.rules.find((ruleItem) => ruleItem.actionPattern.test(lowerName));
  const hasUserSessionIntent = userSessionIntentMatch(actionName, args, spans);

  if (!rule) {
    return {
      sensitiveAction: false,
      requiresUserSession: false,
      allowInert: false,
      hasUserSessionIntent
    };
  }

  return {
    sensitiveAction: rule.sensitive,
    requiresUserSession: rule.requiresUserSession,
    allowInert: rule.allowInert,
    hasUserSessionIntent
  };
}

export function decideAttribution(
  actionName: string,
  args: unknown,
  canaryMap: Record<string, string>,
  spans: Span[],
  sensitivityTable: SensitivityTable = defaultSensitivityTable
): {
  verdict: 'allow' | 'block' | 'flag';
  reason: string;
  attribution: ProvenanceMatchResult;
  canary: CanaryDetectionResult;
  sensitiveAction: boolean;
} {
  const provenanceMatch = argumentProvenanceMatch(args, spans);
  const canary = canaryDetection(JSON.stringify(args ?? null), canaryMap);
  const policy = sensitiveActionPolicy(actionName, args, spans, sensitivityTable);

  if (canary.triggered) {
    if (policy.sensitiveAction) {
      return {
        verdict: 'block',
        reason: `Blocked because canary content from inert span(s) [${canary.triggeredSpanIds.join(', ')}] was reflected in tool arguments.`,
        attribution: provenanceMatch,
        canary,
        sensitiveAction: policy.sensitiveAction
      };
    }

    return {
      verdict: 'flag',
      reason: `Flagged because canary content from inert span(s) [${canary.triggeredSpanIds.join(', ')}] was reflected in tool arguments.`,
      attribution: provenanceMatch,
      canary,
      sensitiveAction: policy.sensitiveAction
    };
  }

  if (policy.sensitiveAction) {
    if (provenanceMatch.inertOnly && !provenanceMatch.actionablePresent) {
      return {
        verdict: 'block',
        reason: 'Blocked because tool arguments originate only from inert spans for a sensitive action.',
        attribution: provenanceMatch,
        canary,
        sensitiveAction: policy.sensitiveAction
      };
    }

    if (policy.requiresUserSession && !policy.hasUserSessionIntent) {
      return {
        verdict: 'block',
        reason: 'Blocked because a sensitive action requires user-session intent that references the action or its arguments.',
        attribution: provenanceMatch,
        canary,
        sensitiveAction: policy.sensitiveAction
      };
    }
  }

  return {
    verdict: 'allow',
    reason: 'Allowed by deterministic provenance checks.',
    attribution: provenanceMatch,
    canary,
    sensitiveAction: policy.sensitiveAction
  };
}
