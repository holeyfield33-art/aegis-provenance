import { describe, expect, it, afterEach } from 'vitest';
import fs from 'fs/promises';
import path from 'path';
import { ReceiptStore } from '../src/receipt-store.js';
import { stableStringify } from '../src/crypto/signing.js';
import { verifyReceiptChain } from '../src/receipt.js';
import type { Receipt } from '../src/types.js';

const storePath = path.resolve('./test-canonicalization-receipts.log');

afterEach(async () => {
  try {
    await fs.unlink(storePath);
  } catch {
    // ignore
  }
});

describe('canonical serialization', () => {
  it('omits undefined-valued object keys, matching JSON round-trip semantics', () => {
    const withUndefined = { type: 'text', tool_name: undefined, tool_args: undefined };
    const reloaded = JSON.parse(JSON.stringify(withUndefined)) as unknown;

    expect(stableStringify(withUndefined)).toBe(stableStringify(reloaded));
    expect(stableStringify(withUndefined)).toBe('{"type":"text"}');
  });

  it('serializes undefined array items as null, matching JSON.stringify', () => {
    const value = ['a', undefined, 'b'];
    expect(stableStringify(value)).toBe(JSON.stringify(value));
  });

  it('receipt chain survives a persistence round trip for text actions', async () => {
    const store = new ReceiptStore(storePath);
    // A text action carries undefined tool_name/tool_args — exactly the shape
    // that JSON drops on write and that must not desync the hash on reload.
    await store.appendReceipt({
      request_id: 'req-text-1',
      ts: new Date().toISOString(),
      span_ids: ['span-1'],
      model_action: { type: 'text', tool_name: undefined, tool_args: undefined },
      attribution: {
        provenanceMatch: { inertOnly: false, actionablePresent: false, matchedSpanIds: [] },
        canaryTriggered: false,
        sensitiveAction: false
      },
      verdict: 'allow',
      reason: 'Allowed by deterministic provenance checks.',
      prev_receipt_hash: ''
    });

    const reloadedStore = new ReceiptStore(storePath);
    const reloaded = await reloadedStore.loadReceipts();
    expect(verifyReceiptChain(reloaded).valid).toBe(true);

    // And the reloaded chain must accept further appends.
    await reloadedStore.appendReceipt({
      request_id: 'req-text-2',
      ts: new Date().toISOString(),
      span_ids: ['span-2'],
      model_action: { type: 'text' },
      attribution: {
        provenanceMatch: { inertOnly: false, actionablePresent: false, matchedSpanIds: [] },
        canaryTriggered: false,
        sensitiveAction: false
      },
      verdict: 'allow',
      reason: 'Allowed by deterministic provenance checks.',
      prev_receipt_hash: ''
    });

    const finalCheck = await reloadedStore.verifyChain();
    expect(finalCheck.valid).toBe(true);
  });

  it('demo receipt log still validates under hardened canonicalization', async () => {
    const demoLog = path.resolve('./aegis-demo-receipts.log');
    const raw = await fs.readFile(demoLog, 'utf8');
    const receipts = raw
      .split('\n')
      .filter((line) => line.trim().length > 0)
      .map((line) => JSON.parse(line) as Receipt);

    expect(receipts.length).toBeGreaterThan(0);
    expect(verifyReceiptChain(receipts).valid).toBe(true);
  });
});
