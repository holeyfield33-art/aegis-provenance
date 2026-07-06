import fs from 'fs';
import { randomBytes } from 'crypto';
import { ed25519 } from '@noble/curves/ed25519.js';

const KEY_ENV = 'AEGIS_SIGNING_KEY';
const KEY_FILE_ENV = 'AEGIS_SIGNING_KEY_FILE';
let cachedSigningKey: Uint8Array | undefined;

function parseHexKey(hex: string): Uint8Array {
  const normalized = hex.trim();
  if (!/^[0-9a-fA-F]+$/.test(normalized) || normalized.length !== 64) {
    throw new Error(`${KEY_ENV} must be a 32-byte hex string`);
  }
  return Uint8Array.from(Buffer.from(normalized, 'hex'));
}

export function loadSigningKey(): Uint8Array {
  const envKey = process.env[KEY_ENV];
  if (envKey) {
    return parseHexKey(envKey);
  }

  const keyFile = process.env[KEY_FILE_ENV];
  if (keyFile) {
    try {
      const fileContents = fs.readFileSync(keyFile, { encoding: 'utf8' });
      return parseHexKey(fileContents);
    } catch (error) {
      throw new Error(`Failed to load signing key from ${KEY_FILE_ENV}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  const generated = randomBytes(32);
  return Uint8Array.from(generated);
}

export function getSigningKey(): Uint8Array {
  if (!cachedSigningKey) {
    cachedSigningKey = loadSigningKey();
  }
  return cachedSigningKey;
}

export function derivePublicKey(secretKey: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(secretKey);
}
