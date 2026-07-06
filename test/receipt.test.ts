import { describe, expect, it } from 'vitest';
import { createReceipt, verifyReceiptChain, GENESIS_HASH } from '../src/receipt.js';
import type { Receipt } from '../src/types.js';

const baseReceipt = (overrides: Partial<Receipt>): Omit<Receipt, 'receipt_hash'> => ({
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
  prev_receipt_hash: GENESIS_HASH
});

describe('Aegis receipt chain', () => {
  it('creates and verifies a valid receipt chain', () => {
    const receipt1 = createReceipt(baseReceipt({ request_id: 'req-1' }));
    const receipt2 = createReceipt({
      ...baseReceipt({ request_id: 'req-2' }),
      prev_receipt_hash: receipt1.receipt_hash
    });

    const result = verifyReceiptChain([receipt1, receipt2]);
    expect(result.valid).toBe(true);
  });

  it('fails verification when a receipt is tampered', () => {
    const receipt1 = createReceipt(baseReceipt({ request_id: 'req-1' }));
    const receipt2 = createReceipt({ ...baseReceipt({ request_id: 'req-2', prev_receipt_hash: receipt1.receipt_hash }), request_id: 'req-2' });
    const tampered = { ...receipt2, verdict: 'block' as const };

    const result = verifyReceiptChain([receipt1, tampered]);
    expect(result.valid).toBe(false);
    expect(result.invalidIndex).toBe(1);
  });
});
