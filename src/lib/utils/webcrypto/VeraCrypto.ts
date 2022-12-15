import { getCiphers } from 'node:crypto';

import { Crypto as BaseCrypto } from '@peculiar/webcrypto';
import { type AesKwProvider, type ProviderCrypto, type SubtleCrypto } from 'webcrypto-core';

import { AwalaAesKwProvider } from './AwalaAesKwProvider.js';

export class VeraCrypto extends BaseCrypto {
  public constructor(customProviders: readonly ProviderCrypto[] = []) {
    super();

    const { providers } = this.subtle as SubtleCrypto;

    const isAesKwSupported = getCiphers().includes('id-aes128-wrap');
    if (!isAesKwSupported) {
      // This must be running on Electron, so let's use a pure JavaScript implementation of AES-KW:
      // https://github.com/relaycorp/relaynet-core-js/issues/367
      const nodejsAesKwProvider = providers.get('AES-KW') as AesKwProvider;
      providers.set(new AwalaAesKwProvider(nodejsAesKwProvider));
    }

    customProviders.forEach((p) => {
      providers.set(p);
    });
  }
}
