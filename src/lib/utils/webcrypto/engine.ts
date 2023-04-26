import { CryptoEngine } from 'pkijs';
import type { ProviderCrypto } from 'webcrypto-core';

import type { CryptoKeyWithProvider } from '../keys/CryptoKeyWithProvider.js';
import { NODE_ENGINE } from '../pkijs.js';

import { VeraCrypto } from './VeraCrypto.js';

const ENGINE_BY_PROVIDER = new WeakMap<ProviderCrypto, CryptoEngine>();

/**
 * Generate and cache PKI.js engine for specified private key.
 */
export function getEngineForPrivateKey(
  privateKey: CryptoKey | CryptoKeyWithProvider,
): CryptoEngine {
  const provider = (privateKey as CryptoKeyWithProvider).provider as ProviderCrypto | undefined;
  if (!provider) {
    return NODE_ENGINE;
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
