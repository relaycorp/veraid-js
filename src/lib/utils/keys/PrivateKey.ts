import {
  CryptoKey as WebCryptoKey,
  type KeyAlgorithm as WebCryptoKeyAlgorithm,
  type ProviderCrypto,
} from 'webcrypto-core';

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
