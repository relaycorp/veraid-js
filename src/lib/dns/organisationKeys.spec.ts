import { getAlgorithmParameters } from 'pkijs';

import type { RsaModulus } from '../utils/algorithms.js';
import { generateRsaKeyPair } from '../utils/keys/generation.js';
import { calculateDigest } from '../../testUtils/crypto.js';
import { derSerializePublicKey } from '../utils/keys/serialisation.js';
import VeraError from '../VeraError.js';
import { getPkijsCrypto } from '../utils/pkijs.js';

import { getKeySpec } from './organisationKeys.js';
import { KeyAlgorithmType } from './KeyAlgorithmType.js';

const CRYPTO_ENGINE = getPkijsCrypto();

async function generatePublicKey(
  algorithm: EcKeyGenParams | RsaHashedKeyGenParams,
): Promise<CryptoKey> {
  const keyPair = await CRYPTO_ENGINE.generateKey(algorithm, true, ['sign', 'verify']);
  return keyPair.publicKey;
}

describe('getKeySpec', () => {
  test.each<[RsaModulus, number, string]>([
    [2048, KeyAlgorithmType.RSA_2048, 'sha256'],
    [3072, KeyAlgorithmType.RSA_3072, 'sha384'],
    [4096, KeyAlgorithmType.RSA_4096, 'sha512'],
  ])('RSA-%s should use algorithm %s and %s', async (modulus, expectedAlgorithm, expectedHash) => {
    const { publicKey } = await generateRsaKeyPair({ modulus });

    const spec = await getKeySpec(publicKey);

    expect(spec.keyAlgorithm).toStrictEqual(expectedAlgorithm);
    const expectedDigest = calculateDigest(
      expectedHash,
      await derSerializePublicKey(publicKey),
    ).toString('base64');
    expect(spec.keyId).toStrictEqual(expectedDigest);
  });

  test('Unsupported RSA modulus should be refused', async () => {
    const algorithm = getAlgorithmParameters('RSA-PSS', 'generateKey');
    const modulusLength = 1024;
    const publicKey = await generatePublicKey({
      ...(algorithm.algorithm as RsaHashedKeyAlgorithm),
      modulusLength,
    });

    await expect(async () => getKeySpec(publicKey)).rejects.toThrowWithMessage(
      VeraError,
      `RSA key with modulus ${modulusLength} is unsupported`,
    );
  });

  test('Non-RSA keys should be refused', async () => {
    const algorithmName = 'ECDSA';
    const publicKey = await generatePublicKey({ name: algorithmName, namedCurve: 'P-256' });

    await expect(async () => getKeySpec(publicKey)).rejects.toThrowWithMessage(
      VeraError,
      `Only RSA-PSS keys are supported (got ${algorithmName})`,
    );
  });
});
