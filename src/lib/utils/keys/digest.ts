import { NODE_ENGINE } from '../pkijs.js';

import { derSerializePublicKey } from './serialisation.js';

/**
 * Return SHA-256 digest of public key.
 */
export async function getPublicKeyDigest(publicKey: CryptoKey): Promise<ArrayBuffer> {
  const publicKeyDer = await derSerializePublicKey(publicKey);
  return NODE_ENGINE.digest({ name: 'SHA-256' }, publicKeyDer);
}
