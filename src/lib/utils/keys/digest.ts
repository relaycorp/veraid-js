import { getPkijsCrypto } from '../pkijs.js';

import { derSerializePublicKey } from './serialisation.js';

const cryptoEngine = getPkijsCrypto();

/**
 * Return SHA-256 digest of public key.
 */
export async function getPublicKeyDigest(publicKey: CryptoKey): Promise<ArrayBuffer> {
  const publicKeyDer = await derSerializePublicKey(publicKey);
  return cryptoEngine.digest({ name: 'SHA-256' }, publicKeyDer);
}
