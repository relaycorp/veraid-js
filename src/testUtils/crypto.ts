import { createHash } from 'node:crypto';

export function calculateDigest(algorithm: string, plaintext: ArrayBuffer | Buffer): Buffer {
  return createHash(algorithm).update(Buffer.from(plaintext)).digest();
}
