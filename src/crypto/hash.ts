import { sha256 } from '@noble/hashes/sha256';

export function sha256Hex(input: Uint8Array | string): string {
  const data = typeof input === 'string' ? new TextEncoder().encode(input) : input;
  return Array.from(sha256(data))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function sha256Bytes(input: Uint8Array | string): Uint8Array {
  const data = typeof input === 'string' ? new TextEncoder().encode(input) : input;
  return sha256(data);
}
