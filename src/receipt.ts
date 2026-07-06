import { sha256Hex } from './crypto/hash.js';
import { canonicalReceiptPayload } from './crypto/signing.js';
import type { Receipt } from './types.js';
import { AegisReceiptError } from './types.js';

export const GENESIS_HASH = '0'.repeat(64);

export function createReceiptHash(receipt: Omit<Receipt, 'receipt_hash'>): string {
  return sha256Hex(canonicalReceiptPayload(receipt));
}

export function createReceipt(receipt: Omit<Receipt, 'receipt_hash'>): Receipt {
  const receiptHash = createReceiptHash(receipt);
  return { ...receipt, receipt_hash: receiptHash };
}

export function verifyReceiptChain(receipts: Receipt[]): { valid: boolean; invalidIndex?: number; message?: string } {
  let prevHash = GENESIS_HASH;

  for (let index = 0; index < receipts.length; index += 1) {
    const receipt = receipts[index];
    if (!receipt) {
      return {
        valid: false,
        invalidIndex: index,
        message: `Receipt ${index} is missing`
      };
    }
    if (receipt.prev_receipt_hash !== prevHash) {
      return {
        valid: false,
        invalidIndex: index,
        message: `Receipt ${index} prev_receipt_hash mismatch: expected ${prevHash}, got ${receipt.prev_receipt_hash}`
      };
    }

    const expectedHash = createReceiptHash({
      request_id: receipt.request_id,
      ts: receipt.ts,
      span_ids: receipt.span_ids,
      model_action: receipt.model_action,
      attribution: receipt.attribution,
      verdict: receipt.verdict,
      reason: receipt.reason,
      prev_receipt_hash: receipt.prev_receipt_hash
    });

    if (receipt.receipt_hash !== expectedHash) {
      return {
        valid: false,
        invalidIndex: index,
        message: `Receipt ${index} hash mismatch: expected ${expectedHash}, got ${receipt.receipt_hash}`
      };
    }

    prevHash = receipt.receipt_hash;
  }

  return { valid: true };
}
