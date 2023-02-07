import type { Attribute } from 'pkijs';

import type { HashingAlgorithm } from '../algorithms.js';

export interface SignatureOptions {
  readonly hashingAlgorithmName: HashingAlgorithm;
  readonly encapsulatePlaintext: boolean;
  readonly extraSignedAttrs: readonly Attribute[];
}
