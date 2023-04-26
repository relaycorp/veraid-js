import { CryptoEngine } from 'pkijs';
import type { ProviderCrypto } from 'webcrypto-core';

import type { CryptoKeyWithProvider } from '../keys/CryptoKeyWithProvider.js';

import { VeraCrypto } from './VeraCrypto.js';

const ENGINE_BY_PROVIDER = new WeakMap<ProviderCrypto, CryptoEngine>();

/**
 * Generate and cache PKI.js engine for specified private key.
 */
export function getEngineForPrivateKey(
  privateKey: CryptoKey | CryptoKeyWithProvider,
): CryptoEngine | undefined {
  const provider = (privateKey as CryptoKeyWithProvider).provider as ProviderCrypto | undefined;
  if (!provider) {
    return undefined;
  }

  const cachedEngine = ENGINE_BY_PROVIDER.get(provider);
  if (cachedEngine) {
    return cachedEngine;
  }

  const crypto = new VeraCrypto([provider]);
  const engine = new CryptoEngine({ crypto });
  ENGINE_BY_PROVIDER.set(provider, engine);
  return engine;
}
