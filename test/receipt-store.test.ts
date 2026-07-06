import { describe, expect, it, afterEach } from 'vitest';
import fs from 'fs/promises';
import path from 'path';
import { ReceiptStore } from '../src/receipt-store.js';

const storePath = path.resolve('./test-receipts.log');

afterEach(async () => {
  try {
    await fs.unlink(storePath);
  } catch {
    // ignore
  }
});

describe('ReceiptStore', () => {
  it('appends receipts and verifies the chain', async () => {
    const store = new ReceiptStore(storePath);
    await store.appendReceipt({
      request_id: 'req-1',
      ts: new Date().toISOString(),
      span_ids: ['span-1'],
      model_action: { type: 'tool_call', tool_name: 'send_email', tool_args: { recipient: 'foo@example.com' } },
      attribution: {
        provenanceMatch: { inertOnly: false, actionablePresent: true, matchedSpanIds: ['span-1'] },
        canaryTriggered: false,
        sensitiveAction: true
      },
      verdict: 'allow',
      reason: 'Allowed by deterministic provenance checks.',
      prev_receipt_hash: ''
    });

    await store.appendReceipt({
      request_id: 'req-2',
      ts: new Date().toISOString(),
      span_ids: ['span-1'],
      model_action: { type: 'tool_call', tool_name: 'send_email', tool_args: { recipient: 'foo@example.com' } },
      attribution: {
        provenanceMatch: { inertOnly: false, actionablePresent: true, matchedSpanIds: ['span-1'] },
        canaryTriggered: false,
        sensitiveAction: true
      },
      verdict: 'allow',
      reason: 'Allowed by deterministic provenance checks.',
      prev_receipt_hash: ''
    });

    const verification = await store.verifyChain();
    expect(verification.valid).toBe(true);
  });

  it('fails to append when the existing receipt chain is invalid', async () => {
    const store = new ReceiptStore(storePath);
    await store.appendReceipt({
      request_id: 'req-1',
      ts: new Date().toISOString(),
      span_ids: ['span-1'],
      model_action: { type: 'tool_call', tool_name: 'send_email', tool_args: { recipient: 'foo@example.com' } },
      attribution: {
        provenanceMatch: { inertOnly: false, actionablePresent: true, matchedSpanIds: ['span-1'] },
        canaryTriggered: false,
        sensitiveAction: true
      },
      verdict: 'allow',
      reason: 'Allowed by deterministic provenance checks.',
      prev_receipt_hash: ''
    });

    await store.appendReceipt({
      request_id: 'req-2',
      ts: new Date().toISOString(),
      span_ids: ['span-1'],
      model_action: { type: 'tool_call', tool_name: 'send_email', tool_args: { recipient: 'foo@example.com' } },
      attribution: {
        provenanceMatch: { inertOnly: false, actionablePresent: true, matchedSpanIds: ['span-1'] },
        canaryTriggered: false,
        sensitiveAction: true
      },
      verdict: 'allow',
      reason: 'Allowed by deterministic provenance checks.',
      prev_receipt_hash: ''
    });

    const raw = await fs.readFile(storePath, 'utf8');
    const lines = raw.trim().split('\n');
    const tampered = JSON.parse(lines[0]!) as any;
    tampered.verdict = 'block';
    await fs.writeFile(storePath, JSON.stringify(tampered) + '\n' + lines[1]! + '\n', 'utf8');

    await expect(
      store.appendReceipt({
        request_id: 'req-3',
        ts: new Date().toISOString(),
        span_ids: ['span-1'],
        model_action: { type: 'tool_call', tool_name: 'send_email', tool_args: { recipient: 'foo@example.com' } },
        attribution: {
          provenanceMatch: { inertOnly: false, actionablePresent: true, matchedSpanIds: ['span-1'] },
          canaryTriggered: false,
          sensitiveAction: true
        },
        verdict: 'allow',
        reason: 'Allowed by deterministic provenance checks.',
        prev_receipt_hash: ''
      })
    ).rejects.toThrow(/invalid chain/);
  });
});
