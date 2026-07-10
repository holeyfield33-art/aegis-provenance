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
   * Injectable fetch implementation. Defaults to the global `fetch` (Node 20+).
   * Tests pass a hand-written fake here — the repo's established mocking style
   * is constructor injection, not `vi.mock`.
   */
  fetchImpl?: typeof fetch;
}

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
 * Parse a raw model completion into a `ModelClientResponse`. Pure and
 * side-effect free so it can be unit-tested directly. Throws `ModelFormatError`
 * on anything that is not a valid envelope — never coerces to a default.
 */
export function parseEnvelope(raw: string): ModelClientResponse {
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
    return { type: 'text', text: content };
  }

  if (type === 'tool_call') {
    const toolName = parsed.tool_name;
    if (typeof toolName !== 'string' || toolName.length === 0) {
      throw new ModelFormatError('tool_call envelope is missing a non-empty "tool_name" field.', raw);
    }
    // tool_args is passed through as-is (unknown). It may be any JSON value;
    // downstream attribution stringifies it defensively.
    return { type: 'tool_call', tool_name: toolName, tool_args: parsed.tool_args };
  }

  throw new ModelFormatError(`Envelope "type" must be "text" or "tool_call", got: ${JSON.stringify(type)}`, raw);
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
  private readonly fetchImpl: typeof fetch;

  constructor(config: OpenAICompatConfig) {
    // Normalize away a trailing slash so `${baseUrl}/chat/completions` is clean.
    this.baseUrl = config.baseUrl.replace(/\/+$/, '');
    this.apiKey = config.apiKey;
    this.model = config.model;
    this.temperature = config.temperature ?? 0;
    this.maxTokens = config.maxTokens ?? 512;
    this.timeoutMs = config.timeoutMs ?? 60000;
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

    return parseEnvelope(content);
  }
}
