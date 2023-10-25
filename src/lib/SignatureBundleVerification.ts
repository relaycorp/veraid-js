import type { VeraMember } from './VeraMember.js';

export interface SignatureBundleVerification {
  readonly plaintext: ArrayBuffer;
  readonly member: VeraMember;
}
