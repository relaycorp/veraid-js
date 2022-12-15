import { createHash } from 'node:crypto';

export function calculateDigest(algorithm: string, plaintext: ArrayBuffer | Buffer): Buffer {
  return createHash(algorithm).update(Buffer.from(plaintext)).digest();
}

export function calculateDigestHex(algorithm: string, plaintext: ArrayBuffer | Buffer): string {
  return calculateDigest(algorithm, plaintext).toString('hex');
}

export function sha256Hex(plaintext: ArrayBuffer | Buffer): string {
  return calculateDigestHex('sha256', plaintext);
}
