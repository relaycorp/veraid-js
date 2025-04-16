import { createHash } from 'node:crypto';
export function calculateDigest(algorithm, plaintext) {
    return createHash(algorithm).update(Buffer.from(plaintext)).digest();
}
//# sourceMappingURL=crypto.js.map