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

  it('serializes concurrent appends into a single valid chain (finding #10)', async () => {
    const store = new ReceiptStore(storePath);
    const makeReceipt = (n: number): Parameters<ReceiptStore['appendReceipt']>[0] => ({
      request_id: `req-${n}`,
      ts: new Date().toISOString(),
      span_ids: [`span-${n}`],
      model_action: { type: 'tool_call', tool_name: 'send_email', tool_args: { recipient: 'foo@example.com' } },
      attribution: {
        provenanceMatch: { inertOnly: false, actionablePresent: true, matchedSpanIds: [`span-${n}`] },
        canaryTriggered: false,
        sensitiveAction: true
      },
      verdict: 'allow',
      reason: 'Allowed by deterministic provenance checks.',
      prev_receipt_hash: ''
    });

    // Fire many appends at once with no awaiting between them. Without
    // serialization these race on the same tail and fork the chain.
    const count = 25;
    const receipts = await Promise.all(
      Array.from({ length: count }, (_unused, index) => store.appendReceipt(makeReceipt(index)))
    );

    // Every append produced a receipt, all persisted, and the chain verifies.
    expect(receipts).toHaveLength(count);
    const loaded = await store.loadReceipts();
    expect(loaded).toHaveLength(count);
    const verification = await store.verifyChain();
    expect(verification.valid).toBe(true);

    // Each receipt links to a distinct predecessor — no two share a prev hash.
    const prevHashes = loaded.map((receipt) => receipt.prev_receipt_hash);
    expect(new Set(prevHashes).size).toBe(count);
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
