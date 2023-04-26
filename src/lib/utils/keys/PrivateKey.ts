import {
  CryptoKey as WebCryptoKey,
  type KeyAlgorithm as WebCryptoKeyAlgorithm,
  type ProviderCrypto,
} from 'webcrypto-core';

import type { CryptoKeyWithProvider } from './CryptoKeyWithProvider.js';

export abstract class PrivateKey extends WebCryptoKey implements CryptoKeyWithProvider {
  public override readonly extractable = true; // The **public** key is extractable as SPKI

  public override readonly type = 'private' as KeyType;

  protected constructor(
    public override readonly algorithm: WebCryptoKeyAlgorithm,
    public readonly provider: ProviderCrypto,
  ) {
    super();
  }
}
