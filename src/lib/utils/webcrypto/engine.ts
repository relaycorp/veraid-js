import { CryptoEngine } from 'pkijs';
import { type ProviderCrypto } from 'webcrypto-core';

import { PrivateKey } from '../PrivateKey.js';

import { VeraCrypto } from './VeraCrypto.js';

const ENGINE_BY_PROVIDER = new WeakMap<ProviderCrypto, CryptoEngine>();

/**
 * Generate and cache PKI.js engine for specified private key.
 */
export function getEngineForPrivateKey(
  privateKey: CryptoKey | PrivateKey,
): CryptoEngine | undefined {
  if (!(privateKey instanceof PrivateKey)) {
    return undefined;
  }

  const cachedEngine = ENGINE_BY_PROVIDER.get(privateKey.provider);
  if (cachedEngine) {
    return cachedEngine;
  }

  const crypto = new VeraCrypto([privateKey.provider]);
  const engine = new CryptoEngine({ crypto });
  ENGINE_BY_PROVIDER.set(privateKey.provider, engine);
  return engine;
}
