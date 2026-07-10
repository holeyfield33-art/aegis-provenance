import { describe, expect, it } from 'vitest';
import {
  OpenAICompatClient,
  ModelFormatError,
  ModelHttpError,
  RateLimitError,
  parseEnvelope,
  stripCodeFences
} from '../src/clients/openai-compat.js';
import type { ProviderMessage } from '../src/types.js';

// Builds a fake `fetch` that returns a chat-completions response whose single
// choice's message.content is `content`, with the given HTTP status.
function fakeFetch(content: string, init?: { status?: number; headers?: Record<string, string> }): typeof fetch {
  const status = init?.status ?? 200;
  const headers = new Headers(init?.headers ?? {});
  const body = JSON.stringify({ choices: [{ message: { content } }] });
  return (async () =>
    new Response(body, { status, headers, statusText: `HTTP ${status}` })) as unknown as typeof fetch;
}

const MESSAGES: ProviderMessage[] = [
  { role: 'system', content: 'You are a helpful assistant.' },
  { role: 'user', content: 'Do the thing.' }
];

describe('parseEnvelope', () => {
  it('parses a valid tool_call envelope', () => {
    const result = parseEnvelope('{"type":"tool_call","tool_name":"send_email","tool_args":{"to":"a@b.example"}}');
    expect(result).toEqual({ type: 'tool_call', tool_name: 'send_email', tool_args: { to: 'a@b.example' } });
  });

  it('parses a valid text envelope', () => {
    const result = parseEnvelope('{"type":"text","content":"hello there"}');
    expect(result).toEqual({ type: 'text', text: 'hello there' });
  });

  it('parses fenced JSON by stripping the code fence', () => {
    const raw = '```json\n{"type":"text","content":"fenced"}\n```';
    expect(parseEnvelope(raw)).toEqual({ type: 'text', text: 'fenced' });
  });

  it('parses a plain ``` fenced tool_call', () => {
    const raw = '```\n{"type":"tool_call","tool_name":"search","tool_args":{"q":"x"}}\n```';
    expect(parseEnvelope(raw)).toEqual({ type: 'tool_call', tool_name: 'search', tool_args: { q: 'x' } });
  });

  it('throws ModelFormatError on garbage (non-JSON) output', () => {
    expect(() => parseEnvelope('Sure! I will send the email now.')).toThrow(ModelFormatError);
  });

  it('throws ModelFormatError on JSON that is not the envelope shape', () => {
    expect(() => parseEnvelope('{"foo":"bar"}')).toThrow(ModelFormatError);
  });

  it('throws ModelFormatError on a tool_call missing tool_name', () => {
    expect(() => parseEnvelope('{"type":"tool_call","tool_args":{}}')).toThrow(ModelFormatError);
  });

  it('throws ModelFormatError on a text envelope missing content', () => {
    expect(() => parseEnvelope('{"type":"text"}')).toThrow(ModelFormatError);
  });

  it('carries the raw text on the error', () => {
    try {
      parseEnvelope('not json at all');
      expect.unreachable('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(ModelFormatError);
      expect((error as ModelFormatError).raw).toBe('not json at all');
    }
  });
});

describe('stripCodeFences', () => {
  it('leaves unfenced JSON untouched', () => {
    expect(stripCodeFences('  {"a":1}  ')).toBe('{"a":1}');
  });

  it('strips a json-tagged fence', () => {
    expect(stripCodeFences('```json\n{"a":1}\n```')).toBe('{"a":1}');
  });
});

describe('OpenAICompatClient.call', () => {
  it('maps a tool_call completion into a ModelClientResponse', async () => {
    const client = new OpenAICompatClient({
      baseUrl: 'https://example.test/v1',
      apiKey: 'k',
      model: 'test-model',
      fetchImpl: fakeFetch('{"type":"tool_call","tool_name":"send_email","tool_args":{"to":"x@y.example"}}')
    });
    const result = await client.call(MESSAGES);
    expect(result).toEqual({ type: 'tool_call', tool_name: 'send_email', tool_args: { to: 'x@y.example' } });
  });

  it('maps a text completion into a ModelClientResponse', async () => {
    const client = new OpenAICompatClient({
      baseUrl: 'https://example.test/v1',
      apiKey: 'k',
      model: 'test-model',
      fetchImpl: fakeFetch('{"type":"text","content":"ok"}')
    });
    const result = await client.call(MESSAGES);
    expect(result).toEqual({ type: 'text', text: 'ok' });
  });

  it('throws RateLimitError on HTTP 429 with a numeric retry-after', async () => {
    const client = new OpenAICompatClient({
      baseUrl: 'https://example.test/v1',
      apiKey: 'k',
      model: 'test-model',
      fetchImpl: fakeFetch('', { status: 429, headers: { 'retry-after': '7' } })
    });
    await expect(client.call(MESSAGES)).rejects.toBeInstanceOf(RateLimitError);
    try {
      await client.call(MESSAGES);
    } catch (error) {
      expect((error as RateLimitError).retryAfterMs).toBe(7000);
    }
  });

  it('throws ModelHttpError on other non-2xx responses', async () => {
    const client = new OpenAICompatClient({
      baseUrl: 'https://example.test/v1',
      apiKey: 'k',
      model: 'test-model',
      fetchImpl: fakeFetch('server exploded', { status: 500 })
    });
    await expect(client.call(MESSAGES)).rejects.toBeInstanceOf(ModelHttpError);
  });

  it('throws ModelFormatError when the completion is unparseable', async () => {
    const client = new OpenAICompatClient({
      baseUrl: 'https://example.test/v1',
      apiKey: 'k',
      model: 'test-model',
      fetchImpl: fakeFetch('I cannot comply with that.')
    });
    await expect(client.call(MESSAGES)).rejects.toBeInstanceOf(ModelFormatError);
  });

  it('sends the model, temperature, and appends the envelope instruction', async () => {
    let captured: { url: string; body: unknown } | null = null;
    const capturingFetch = (async (url: string, init?: RequestInit) => {
      captured = { url, body: JSON.parse(String(init?.body)) };
      return new Response(JSON.stringify({ choices: [{ message: { content: '{"type":"text","content":"hi"}' } }] }), {
        status: 200
      });
    }) as unknown as typeof fetch;

    const client = new OpenAICompatClient({
      baseUrl: 'https://example.test/v1/',
      apiKey: 'secret',
      model: 'my-model',
      temperature: 0,
      fetchImpl: capturingFetch
    });
    await client.call(MESSAGES);

    expect(captured).not.toBeNull();
    const body = captured!.body as { model: string; temperature: number; messages: ProviderMessage[] };
    // Trailing slash on baseUrl is normalized away.
    expect(captured!.url).toBe('https://example.test/v1/chat/completions');
    expect(body.model).toBe('my-model');
    expect(body.temperature).toBe(0);
    // Original messages + one appended system instruction.
    expect(body.messages).toHaveLength(MESSAGES.length + 1);
    const last = body.messages[body.messages.length - 1]!;
    expect(last.role).toBe('system');
    expect(last.content).toContain('EXACTLY ONE JSON object');
  });
});
