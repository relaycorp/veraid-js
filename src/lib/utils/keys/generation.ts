import { bufferToArray } from '../buffers.js';
import type { HashingAlgorithm, RsaModulus } from '../algorithms.js';
import { NODE_ENGINE } from '../pkijs.js';

import { derSerializePublicKey } from './serialisation.js';

const MIN_RSA_MODULUS = 2048;

export interface RsaKeyGenOptions {
  readonly modulus: RsaModulus;
  readonly hashingAlgorithm: HashingAlgorithm;
}

/**
 * Generate an RSA-PSS key pair.
 *
 * @param options The RSA key generation options
 * @throws Error If the modulus or the hashing algorithm is disallowed.
 */
export async function generateRsaKeyPair(
  options: Partial<RsaKeyGenOptions> = {},
): Promise<CryptoKeyPair> {
  const modulus = options.modulus ?? MIN_RSA_MODULUS;
  if (modulus < MIN_RSA_MODULUS) {
    throw new Error(`RSA modulus must be => 2048 (got ${modulus})`);
  }

  const hashingAlgorithm = options.hashingAlgorithm ?? 'SHA-256';

  if ((hashingAlgorithm as any) === 'SHA-1') {
    throw new Error('SHA-1 is unsupported');
  }

  const algorithm = NODE_ENGINE.getAlgorithmParameters('RSA-PSS', 'generateKey');
  const rsaAlgorithm = algorithm.algorithm as RsaHashedKeyAlgorithm;

  rsaAlgorithm.hash.name = hashingAlgorithm;

  rsaAlgorithm.modulusLength = modulus;

  return NODE_ENGINE.generateKey(rsaAlgorithm, true, algorithm.usages);
}

export async function getRsaPublicKeyFromPrivate(privateKey: CryptoKey): Promise<CryptoKey> {
  const publicKeyDer = bufferToArray(await derSerializePublicKey(privateKey));
  return NODE_ENGINE.importKey('spki', publicKeyDer, privateKey.algorithm, true, ['verify']);
}
