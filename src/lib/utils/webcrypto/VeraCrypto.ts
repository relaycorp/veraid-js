import { Crypto as BaseCrypto } from '@peculiar/webcrypto';
import type {
  ProviderCrypto,
  RsaPssProvider as BaseRsaPssProvider,
  SubtleCrypto,
} from 'webcrypto-core';

import { RsaPssProvider } from './RsaPssProvider.js';

export class VeraCrypto extends BaseCrypto {
  public constructor(additionalProviders: readonly ProviderCrypto[] = []) {
    super();

    const { providers } = this.subtle as SubtleCrypto;

    additionalProviders.forEach((provider) => {
      providers.set(provider);
    });

    const originalRsaPssProvider = providers.get('RSA-PSS') as BaseRsaPssProvider;
    const newRsaPssProvider = new RsaPssProvider(originalRsaPssProvider);
    providers.set(newRsaPssProvider);
  }
}
