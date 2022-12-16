import { Crypto as BaseCrypto } from '@peculiar/webcrypto';
import { type ProviderCrypto, type SubtleCrypto } from 'webcrypto-core';

export class VeraCrypto extends BaseCrypto {
  public constructor(additionalProviders: readonly ProviderCrypto[] = []) {
    super();

    const { providers } = this.subtle as SubtleCrypto;

    additionalProviders.forEach((provider) => {
      providers.set(provider);
    });
  }
}
