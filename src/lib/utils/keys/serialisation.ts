import { CRYPTO_ENGINE } from '../pkijs.js';
import { bufferToArray } from '../buffers.js';

import { PrivateKey } from './PrivateKey.js';

const DEFAULT_RSA_KEY_PARAMS: RsaHashedImportParams = {
  hash: { name: 'SHA-256' },
  name: 'RSA-PSS',
};

/**
 * Return DER serialization of public key.
 */
export async function derSerializePublicKey(publicKey: CryptoKey): Promise<Buffer> {
  const publicKeyDer =
    publicKey instanceof PrivateKey
      ? ((await publicKey.provider.exportKey('spki', publicKey)) as ArrayBuffer)
      : await CRYPTO_ENGINE.exportKey('spki', publicKey);
  return Buffer.from(publicKeyDer);
}

/**
 * Return DER serialization of private key.
 */
export async function derSerializePrivateKey(privateKey: CryptoKey): Promise<Buffer> {
  const keyDer = await CRYPTO_ENGINE.exportKey('pkcs8', privateKey);
  return Buffer.from(keyDer);
}

/**
 * Parse DER-serialized RSA public key.
 */
export async function derDeserializeRsaPublicKey(
  publicKeyDer: ArrayBuffer | Buffer,
  algorithmOptions: RsaHashedImportParams = DEFAULT_RSA_KEY_PARAMS,
): Promise<CryptoKey> {
  const keyData = publicKeyDer instanceof Buffer ? bufferToArray(publicKeyDer) : publicKeyDer;
  return CRYPTO_ENGINE.importKey('spki', keyData, algorithmOptions, true, ['verify']);
}

/**
 * Parse DER-serialized RSA private key.
 */
export async function derDeserializeRsaPrivateKey(
  privateKeyDer: Buffer,
  algorithmOptions: RsaHashedImportParams = DEFAULT_RSA_KEY_PARAMS,
): Promise<CryptoKey> {
  return CRYPTO_ENGINE.importKey('pkcs8', bufferToArray(privateKeyDer), algorithmOptions, true, [
    'sign',
  ]);
}
