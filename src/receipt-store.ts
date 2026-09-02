import fs from 'fs/promises';
import { createReceipt, verifyReceiptChain, GENESIS_HASH } from './receipt.js';
import type { Receipt } from './types.js';
import { AegisReceiptError } from './types.js';

export class ReceiptStore {
  // Serializes appends within this process. appendReceipt is read-modify-write
  // (read the tail to find the previous hash, then append), so two concurrent
  // calls could otherwise read the same tail and write two receipts that both
  // point at the same prev_receipt_hash — a forked, corrupt chain (finding
  // #10). Chaining every append onto this promise makes the critical section
  // atomic for this process's callers. (Cross-process writers to the same file
  // still need external coordination; that is documented as a limitation.)
  private appendQueue: Promise<unknown> = Promise.resolve();

  constructor(public readonly filePath: string) {}

  public async loadReceipts(): Promise<Receipt[]> {
    try {
      const content = await fs.readFile(this.filePath, { encoding: 'utf8' });
      return content
        .split('\n')
        .filter((line) => line.trim().length > 0)
        .map((line) => JSON.parse(line) as Receipt);
    } catch (error) {
      if (error instanceof Error && 'code' in error && (error as NodeJS.ErrnoException).code === 'ENOENT') {
        return [];
      }
      throw new AegisReceiptError(`Failed to load receipts: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  public async appendReceipt(receiptData: Omit<Receipt, 'receipt_hash'>): Promise<Receipt> {
    // Run the whole read-modify-write under the per-store serialization queue so
    // concurrent callers cannot interleave and fork the hash chain. Failures are
    // isolated: the queue continues past a rejected append rather than wedging
    // every subsequent call.
    const run = this.appendQueue.then(
      () => this.appendReceiptUnlocked(receiptData),
      () => this.appendReceiptUnlocked(receiptData)
    );
    // Keep the chain alive on rejection: swallow the error on the queue tail
    // (the caller still receives it via `run`).
    this.appendQueue = run.catch(() => undefined);
    return run;
  }

  private async appendReceiptUnlocked(receiptData: Omit<Receipt, 'receipt_hash'>): Promise<Receipt> {
    const receipts = await this.loadReceipts();
    const chainCheck = verifyReceiptChain(receipts);
    if (!chainCheck.valid) {
      throw new AegisReceiptError(`Receipt store contains an invalid chain: ${chainCheck.message}`);
    }

    const lastReceipt = receipts[receipts.length - 1];
    const prevReceiptHash = lastReceipt ? lastReceipt.receipt_hash : GENESIS_HASH;
    const receipt = createReceipt({ ...receiptData, prev_receipt_hash: prevReceiptHash });

    try {
      await fs.appendFile(this.filePath, JSON.stringify(receipt) + '\n', { encoding: 'utf8' });
      return receipt;
    } catch (error) {
      throw new AegisReceiptError(`Failed to append receipt: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  public async verifyChain(): Promise<{ valid: boolean; invalidIndex?: number; message?: string }> {
    const receipts = await this.loadReceipts();
    return verifyReceiptChain(receipts);
  }
}
