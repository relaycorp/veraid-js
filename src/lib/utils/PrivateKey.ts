import {
  CryptoKey as WebCryptoKey,
  type KeyAlgorithm as WebCryptoKeyAlgorithm,
  type KeyUsages,
  type ProviderCrypto,
} from 'webcrypto-core';

import { type HashingAlgorithm } from './algorithms.js';

export abstract class PrivateKey extends WebCryptoKey {
  public override readonly extractable = true; // The **public** key is extractable as SPKI

  public override readonly type = 'private' as KeyType;

  protected constructor(
    public override readonly algorithm: WebCryptoKeyAlgorithm,
    public readonly provider: ProviderCrypto,
  ) {
    super();
  }
}

export class RsaPssPrivateKey extends PrivateKey {
  public override readonly usages = ['sign'] as KeyUsages;

  public constructor(hashingAlgorithm: HashingAlgorithm, provider: ProviderCrypto) {
    const algorithm = { name: 'RSA-PSS', hash: { name: hashingAlgorithm } };
    super(algorithm, provider);
  }
}
