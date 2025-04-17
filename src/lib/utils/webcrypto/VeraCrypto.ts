import { Crypto as BaseCrypto } from '@peculiar/webcrypto';
import type {
  RsaPssProvider as BaseRsaPssProvider,
  ProviderCrypto,
  SubtleCrypto,
} from 'webcrypto-core';

import { RsaPssProvider } from './RsaPssProvider.js';

export class VeraCrypto extends BaseCrypto {
  public constructor(
    shouldUseCustomRsaPssProvider: boolean,
    additionalProviders: readonly ProviderCrypto[] = [],
  ) {
    super();

    const { providers } = this.subtle as SubtleCrypto;

    for (const provider of additionalProviders) {
      providers.set(provider);
    }

    if (shouldUseCustomRsaPssProvider) {
      const originalRsaPssProvider = providers.get('RSA-PSS') as BaseRsaPssProvider;
      const newRsaPssProvider = new RsaPssProvider(originalRsaPssProvider);
      providers.set(newRsaPssProvider);
    }
  }
}
