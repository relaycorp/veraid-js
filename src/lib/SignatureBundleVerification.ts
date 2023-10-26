import type { Member } from './Member.js';

export interface SignatureBundleVerification {
  readonly plaintext: ArrayBuffer;
  readonly member: Member;
}
