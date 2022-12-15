import bufferToArray from 'buffer-to-arraybuffer';
import { getAlgorithmParameters } from 'pkijs';

import { getPkijsCrypto } from './pkijs.js';
import { type HashingAlgorithm, type RsaModulus } from './algorithms.js';
import { PrivateKey } from './PrivateKey.js';

const cryptoEngine = getPkijsCrypto();

const MIN_RSA_MODULUS = 2048;

const DEFAULT_RSA_KEY_PARAMS: RsaHashedImportParams = {
  hash: { name: 'SHA-256' },
  name: 'RSA-PSS',
};

export interface RsaKeyGenOptions {
  readonly modulus: RsaModulus;
  readonly hashingAlgorithm: HashingAlgorithm;
}

/**
 * Return DER serialization of public key.
 */
export async function derSerializePublicKey(publicKey: CryptoKey): Promise<Buffer> {
  const publicKeyDer =
    publicKey instanceof PrivateKey
      ? ((await publicKey.provider.exportKey('spki', publicKey)) as ArrayBuffer)
      : await cryptoEngine.exportKey('spki', publicKey);
  return Buffer.from(publicKeyDer);
}

/**
 * Return DER serialization of private key.
 */
export async function derSerializePrivateKey(privateKey: CryptoKey): Promise<Buffer> {
  const keyDer = await cryptoEngine.exportKey('pkcs8', privateKey);
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
  return cryptoEngine.importKey('spki', keyData, algorithmOptions, true, ['verify']);
}

/**
 * Parse DER-serialized RSA private key.
 */
export async function derDeserializeRsaPrivateKey(
  privateKeyDer: Buffer,
  algorithmOptions: RsaHashedImportParams = DEFAULT_RSA_KEY_PARAMS,
): Promise<CryptoKey> {
  return cryptoEngine.importKey('pkcs8', bufferToArray(privateKeyDer), algorithmOptions, true, [
    'sign',
  ]);
}

/**
 * Generate an RSA-PSS key pair.
 *
 * @param options The RSA key generation options
 * @throws Error If the modulus or the hashing algorithm is disallowed by RS-018.
 */
export async function generateRsaKeyPair(
  options: Partial<RsaKeyGenOptions> = {},
): Promise<CryptoKeyPair> {
  const modulus = options.modulus ?? MIN_RSA_MODULUS;
  if (modulus < MIN_RSA_MODULUS) {
    throw new Error(`RSA modulus must be => 2048 per RS-018 (got ${modulus})`);
  }

  const hashingAlgorithm = options.hashingAlgorithm ?? 'SHA-256';

  // RS-018 disallows MD5 and SHA-1, but only SHA-1 is supported in WebCrypto
  if ((hashingAlgorithm as any) === 'SHA-1') {
    throw new Error('SHA-1 is disallowed by RS-018');
  }

  const algorithm = getAlgorithmParameters('RSA-PSS', 'generateKey');
  const rsaAlgorithm = algorithm.algorithm as RsaHashedKeyAlgorithm;

  rsaAlgorithm.hash.name = hashingAlgorithm;

  rsaAlgorithm.modulusLength = modulus;

  return cryptoEngine.generateKey(rsaAlgorithm, true, algorithm.usages);
}

export async function getRsaPublicKeyFromPrivate(privateKey: CryptoKey): Promise<CryptoKey> {
  const publicKeyDer = bufferToArray(await derSerializePublicKey(privateKey));
  return cryptoEngine.importKey('spki', publicKeyDer, privateKey.algorithm, true, ['verify']);
}

/**
 * Return SHA-256 digest of public key.
 */
export async function getPublicKeyDigest(publicKey: CryptoKey): Promise<ArrayBuffer> {
  const publicKeyDer = await derSerializePublicKey(publicKey);
  return cryptoEngine.digest({ name: 'SHA-256' }, publicKeyDer);
}

/**
 * Return hexadecimal, SHA-256 digest of public key.
 */
export async function getPublicKeyDigestHex(publicKey: CryptoKey): Promise<string> {
  const digest = Buffer.from(await getPublicKeyDigest(publicKey));
  return digest.toString('hex');
}

export async function getIdFromIdentityKey(identityPublicKey: CryptoKey): Promise<string> {
  const algorithmName = identityPublicKey.algorithm.name;
  if (!algorithmName.startsWith('RSA-')) {
    throw new Error(`Only RSA keys are supported (got ${algorithmName})`);
  }
  const keyDigest = await getPublicKeyDigestHex(identityPublicKey);
  return `0${keyDigest}`;
}
