import type { KeyUsages, ProviderCrypto } from 'webcrypto-core';

import type { HashingAlgorithm } from '../algorithms.js';

import { PrivateKey } from './PrivateKey.js';

export class RsaPssPrivateKey extends PrivateKey {
  public override readonly usages = ['sign'] as KeyUsages;

  public constructor(hashingAlgorithm: HashingAlgorithm, provider: ProviderCrypto) {
    const algorithm = { name: 'RSA-PSS', hash: { name: hashingAlgorithm } };
    super(algorithm, provider);
  }
}
