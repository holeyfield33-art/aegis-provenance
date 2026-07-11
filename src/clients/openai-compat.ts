import type { ModelClient, ModelClientResponse } from '../harness.js';
import type { ProviderMessage, ProviderRole } from '../types.js';

/**
 * OpenAI-compatible model client for Phase 2 real-model evaluation.
 * ----------------------------------------------------------------
 * A single adapter that talks to any OpenAI-compatible `/chat/completions`
 * endpoint. It serves both evaluation paths:
 *   - Path A: Hugging Face Inference Providers router
 *     (https://router.huggingface.co/v1)
 *   - Path B: a local llama.cpp OpenAI-compatible server
 *     (http://127.0.0.1:8000/v1)
 *
 * Small open models expose native `tools` support inconsistently, so instead of
 * relying on it we instruct the model to emit a strict JSON envelope and parse
 * that into a `ModelClientResponse`. A parse failure is treated as data (a
 * `ModelFormatError`), never silently coerced to a text answer — the eval
 * runner records format-compliance as its own metric.
 */

/**
 * Thrown when the model's completion cannot be parsed into the required JSON
 * envelope. Carries the raw text so the eval runner can record it. Follows the
 * `AegisError` naming pattern (extends `Error`, sets `name`) but is deliberately
 * kept out of `src/types.ts` so existing enforcement code is untouched.
 */
export class ModelFormatError extends Error {
  public readonly raw: string;

  constructor(message: string, raw: string) {
    super(message);
    this.name = 'ModelFormatError';
    this.raw = raw;
  }
}

/** Thrown on an HTTP 429 so the runner can back off and retry only this case. */
export class RateLimitError extends Error {
  public readonly retryAfterMs?: number;

  constructor(message: string, retryAfterMs?: number) {
    super(message);
    this.name = 'RateLimitError';
    this.retryAfterMs = retryAfterMs;
  }
}

/** Thrown for non-2xx responses other than 429. */
export class ModelHttpError extends Error {
  public readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = 'ModelHttpError';
    this.status = status;
  }
}

export interface OpenAICompatConfig {
  baseUrl: string;
  apiKey: string;
  model: string;
  /** Sampling temperature. Defaults to 0 for reproducible evaluation. */
  temperature?: number;
  /** Max tokens for the completion. Defaults to 512 (envelopes are short). */
  maxTokens?: number;
  /** Per-request timeout in milliseconds. Defaults to 60000. */
  timeoutMs?: number;
  /**
   * Registered tool names. Passed into `parseEnvelope` so the tolerant path can
   * validate a normalized tool name against the real toolset. Defaults to empty
   * (no normalization — strict envelopes only).
   */
  allowedTools?: Iterable<string>;
  /**
   * Injectable fetch implementation. Defaults to the global `fetch` (Node 20+).
   * Tests pass a hand-written fake here — the repo's established mocking style
   * is constructor injection, not `vi.mock`.
   */
  fetchImpl?: typeof fetch;
}

// Task 4 (future seam, not implemented): Qwen2.5 and other newer small models
// support OpenAI-native `tools`/`tool_choice`. The JSON envelope was chosen for
// portability across endpoints that expose native tool-calling inconsistently.
// A future `useNativeTools` option on `OpenAICompatConfig` could send the real
// `tools` array and read `message.tool_calls` instead of appending
// `ENVELOPE_INSTRUCTION` and parsing an envelope — for models that support it —
// while leaving the envelope path as the portable default. Out of scope here.

/**
 * Fixed instruction appended as a final system message. It forces the model to
 * answer with exactly one JSON object and nothing else, mirroring the two
 * shapes of `ModelClientResponse`.
 */
export const ENVELOPE_INSTRUCTION = [
  'You must respond with EXACTLY ONE JSON object and nothing else.',
  'Do not include any prose, explanation, or markdown code fences.',
  'Use one of these two shapes:',
  '  {"type":"text","content":"<your answer as a string>"}',
  '  {"type":"tool_call","tool_name":"<one tool name>","tool_args":{<arguments object>}}',
  'Emit a tool_call only when an action should be taken; otherwise emit text.'
].join('\n');

interface ChatCompletionMessage {
  role: ProviderRole;
  content: string;
}

interface ChatCompletionChoice {
  message?: { content?: unknown };
}

interface ChatCompletionResponse {
  choices?: ChatCompletionChoice[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Strip an optional ```` ```json ... ``` ```` (or plain ```` ``` ````) fence and
 * surrounding whitespace from a model completion.
 */
export function stripCodeFences(raw: string): string {
  const trimmed = raw.trim();
  const fenceMatch = trimmed.match(/^```(?:json|JSON)?\s*\n?([\s\S]*?)\n?```$/);
  if (fenceMatch && typeof fenceMatch[1] === 'string') {
    return fenceMatch[1].trim();
  }
  return trimmed;
}

/**
 * A `ModelClientResponse` carrying an extra, non-contract `normalized` marker.
 * Set true when the tolerant parse path recovered a tool_call from a near-miss
 * envelope shape (e.g. `{"type":"email"}`). The harness passes the response
 * object through untouched, so the eval runner can read this flag off the exact
 * response for a cell — race-free even when a client is shared across a pool.
 */
export interface NormalizableResponse extends ModelClientResponse {
  normalized?: boolean;
}

/** Result of a detailed parse: the response plus whether normalization fired. */
export interface ParsedEnvelope {
  response: ModelClientResponse;
  normalized: boolean;
}

/** Split an identifier into lowercase alphanumeric tokens (e.g. send_email → {send,email}). */
function tokenize(value: string): Set<string> {
  return new Set(
    value
      .toLowerCase()
      .split(/[^a-z0-9]+/)
      .filter((token) => token.length > 0)
  );
}

function isSubset(a: Set<string>, b: Set<string>): boolean {
  for (const token of a) {
    if (!b.has(token)) {
      return false;
    }
  }
  return true;
}

/**
 * Find the single registered tool a candidate name refers to. Exact match wins;
 * otherwise a candidate matches a tool when their token sets are subset-related
 * (so `email` and `email_send` both resolve to `send_email`). Returns
 * `ambiguous` when more than one registered tool matches (e.g. `file` matches
 * both `read_file` and `delete_file`), so the caller can refuse rather than guess.
 */
function findMatchingTool(candidate: string, allowed: Set<string>): { match?: string; ambiguous: boolean } {
  if (allowed.has(candidate)) {
    return { match: candidate, ambiguous: false };
  }
  const candTokens = tokenize(candidate);
  if (candTokens.size === 0) {
    return { ambiguous: false };
  }
  const matches = [...allowed].filter((name) => {
    const toolTokens = tokenize(name);
    return isSubset(candTokens, toolTokens) || isSubset(toolTokens, candTokens);
  });
  if (matches.length === 1) {
    return { match: matches[0], ambiguous: false };
  }
  if (matches.length > 1) {
    return { ambiguous: true };
  }
  return { ambiguous: false };
}

/**
 * Parse a raw model completion into a `ModelClientResponse` plus a `normalized`
 * flag. Pure and side-effect free so it can be unit-tested directly. Throws
 * `ModelFormatError` on anything that is not a valid (or recoverable) envelope —
 * never coerces to a default.
 *
 * Strict `text`/`tool_call` envelopes parse exactly as before (`normalized:false`).
 * If `type` is neither but a non-empty string field names a registered tool —
 * the `type` value itself, or a top-level `tool`/`action`/`name` field — and a
 * single registered tool matches, it is normalized to a tool_call
 * (`normalized:true`). Ambiguous matches or no match still throw: parse failure
 * remains data.
 */
export function parseEnvelopeDetailed(raw: string, allowedTools?: Iterable<string>): ParsedEnvelope {
  const cleaned = stripCodeFences(raw);
  if (cleaned.length === 0) {
    throw new ModelFormatError('Model returned an empty response.', raw);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(cleaned);
  } catch {
    throw new ModelFormatError('Model response was not valid JSON.', raw);
  }

  if (!isRecord(parsed)) {
    throw new ModelFormatError('Model response was not a JSON object.', raw);
  }

  const type = parsed.type;
  if (type === 'text') {
    const content = parsed.content;
    if (typeof content !== 'string') {
      throw new ModelFormatError('text envelope is missing a string "content" field.', raw);
    }
    return { response: { type: 'text', text: content }, normalized: false };
  }

  if (type === 'tool_call') {
    const toolName = parsed.tool_name;
    if (typeof toolName !== 'string' || toolName.length === 0) {
      throw new ModelFormatError('tool_call envelope is missing a non-empty "tool_name" field.', raw);
    }
    // tool_args is passed through as-is (unknown). It may be any JSON value;
    // downstream attribution stringifies it defensively.
    return { response: { type: 'tool_call', tool_name: toolName, tool_args: parsed.tool_args }, normalized: false };
  }

  // Tolerant path: recover a tool_call from a near-miss shape, but only when a
  // single registered tool matches. Gathers candidate names from the `type`
  // value and common top-level fields.
  const allowed = new Set(allowedTools ?? []);
  if (allowed.size > 0) {
    const candidates: string[] = [];
    if (typeof type === 'string' && type.length > 0) {
      candidates.push(type);
    }
    for (const key of ['tool', 'action', 'name'] as const) {
      const value = parsed[key];
      if (typeof value === 'string' && value.length > 0) {
        candidates.push(value);
      }
    }
    const matched = new Set<string>();
    let sawAmbiguous = false;
    for (const candidate of candidates) {
      const result = findMatchingTool(candidate, allowed);
      if (result.ambiguous) {
        sawAmbiguous = true;
      }
      if (result.match) {
        matched.add(result.match);
      }
    }
    if (!sawAmbiguous && matched.size === 1) {
      const toolName = [...matched][0]!;
      const toolArgs = parsed.tool_args ?? parsed.args ?? parsed.arguments ?? parsed.parameters;
      return { response: { type: 'tool_call', tool_name: toolName, tool_args: toolArgs }, normalized: true };
    }
  }

  throw new ModelFormatError(`Envelope "type" must be "text" or "tool_call", got: ${JSON.stringify(type)}`, raw);
}

/**
 * Backward-compatible parse that returns just the `ModelClientResponse`. Passes
 * `allowedTools` through to enable the tolerant normalization path.
 */
export function parseEnvelope(raw: string, allowedTools?: Iterable<string>): ModelClientResponse {
  return parseEnvelopeDetailed(raw, allowedTools).response;
}

function parseRetryAfterMs(header: string | null): number | undefined {
  if (!header) {
    return undefined;
  }
  const seconds = Number(header);
  if (Number.isFinite(seconds)) {
    return Math.max(0, seconds * 1000);
  }
  const dateMs = Date.parse(header);
  if (Number.isFinite(dateMs)) {
    return Math.max(0, dateMs - Date.now());
  }
  return undefined;
}

export class OpenAICompatClient implements ModelClient {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly model: string;
  private readonly temperature: number;
  private readonly maxTokens: number;
  private readonly timeoutMs: number;
  private readonly allowedTools: Set<string>;
  private readonly fetchImpl: typeof fetch;

  constructor(config: OpenAICompatConfig) {
    // Normalize away a trailing slash so `${baseUrl}/chat/completions` is clean.
    this.baseUrl = config.baseUrl.replace(/\/+$/, '');
    this.apiKey = config.apiKey;
    this.model = config.model;
    this.temperature = config.temperature ?? 0;
    this.maxTokens = config.maxTokens ?? 512;
    this.timeoutMs = config.timeoutMs ?? 60000;
    this.allowedTools = new Set(config.allowedTools ?? []);
    this.fetchImpl = config.fetchImpl ?? fetch;
  }

  async call(messages: ProviderMessage[]): Promise<ModelClientResponse> {
    // `metadata` is dropped: the OpenAI chat schema has no field for it. Only
    // role + content cross the wire. The envelope instruction is appended last
    // so it is the final thing the model reads.
    const requestMessages: ChatCompletionMessage[] = messages.map((message) => ({
      role: message.role,
      content: message.content
    }));
    requestMessages.push({ role: 'system', content: ENVELOPE_INSTRUCTION });

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    let response: Response;
    try {
      response = await this.fetchImpl(`${this.baseUrl}/chat/completions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${this.apiKey}`
        },
        body: JSON.stringify({
          model: this.model,
          temperature: this.temperature,
          max_tokens: this.maxTokens,
          messages: requestMessages
        }),
        signal: controller.signal
      });
    } finally {
      clearTimeout(timeout);
    }

    if (response.status === 429) {
      const retryAfterMs = parseRetryAfterMs(response.headers.get('retry-after'));
      throw new RateLimitError(`Rate limited by ${this.baseUrl} (HTTP 429).`, retryAfterMs);
    }

    if (!response.ok) {
      const bodySnippet = (await response.text().catch(() => '')).slice(0, 500);
      throw new ModelHttpError(
        `Model endpoint returned HTTP ${response.status}: ${bodySnippet}`,
        response.status
      );
    }

    const data = (await response.json()) as ChatCompletionResponse;
    const firstChoice = data.choices?.[0];
    const content = firstChoice?.message?.content;
    if (typeof content !== 'string') {
      throw new ModelFormatError(
        'Completion did not contain a string message.content.',
        JSON.stringify(data).slice(0, 500)
      );
    }

    const parsed = parseEnvelopeDetailed(content, this.allowedTools);
    if (!parsed.normalized) {
      return parsed.response;
    }
    // Attach the non-contract marker onto this exact response object so the eval
    // runner can attribute normalization to this cell (harness passes it through
    // untouched). The harness ignores the extra field.
    const out: NormalizableResponse = { ...parsed.response, normalized: true };
    return out;
  }
}
