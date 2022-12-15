/**
 * Plain RSA signatures are used when CMS SignedData can't be used. That is, when the signer
 * doesn't (yet) have a certificate.
 */

import { getPkijsCrypto } from './pkijs.js';
import { PrivateKey } from './PrivateKey.js';

const rsaPssParameters = {
  hash: { name: 'SHA-256' },
  name: 'RSA-PSS',
  saltLength: 32,
};

const pkijsCrypto = getPkijsCrypto();

export async function sign(plaintext: ArrayBuffer, privateKey: CryptoKey): Promise<ArrayBuffer> {
  if (privateKey instanceof PrivateKey) {
    return privateKey.provider.sign(rsaPssParameters, privateKey, plaintext);
  }
  return pkijsCrypto.sign(rsaPssParameters, privateKey, plaintext);
}

export async function verify(
  signature: ArrayBuffer,
  publicKey: CryptoKey,
  expectedPlaintext: ArrayBuffer,
): Promise<boolean> {
  return pkijsCrypto.verify(rsaPssParameters, publicKey, signature, expectedPlaintext);
}
