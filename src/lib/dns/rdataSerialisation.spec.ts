import { secondsInDay } from 'date-fns';
import { getAlgorithmParameters } from 'pkijs';

import { type RsaModulus } from '../utils/algorithms.js';
import { derSerializePublicKey, generateRsaKeyPair } from '../utils/keys.js';
import { getPkijsCrypto } from '../utils/pkijs.js';
import VeraError from '../VeraError.js';
import { KeyIdType } from '../KeyIdType.js';
import { calculateDigest } from '../../testUtils/crypto.js';

import { generateTxtRdata } from './rdataSerialisation.js';

const TTL_OVERRIDE = 42;

const CRYPTO_ENGINE = getPkijsCrypto();

async function generatePublicKey(
  algorithm: EcKeyGenParams | RsaHashedKeyGenParams,
): Promise<CryptoKey> {
  const keyPair = await CRYPTO_ENGINE.generateKey(algorithm, true, ['sign', 'verify']);
  return keyPair.publicKey;
}

describe('generateTxtRdata', () => {
  let rsaPublicKey: CryptoKey;
  beforeAll(async () => {
    const rsaKeyPair = await generateRsaKeyPair();
    rsaPublicKey = rsaKeyPair.publicKey;
  });

  function splitAndGetField(rdata: string, index: number): string | undefined {
    return rdata.split(' ')[index];
  }

  describe('Key algorithm', () => {
    test.each<[RsaModulus, number]>([
      [2048, 0],
      [3072, 1],
      [4096, 2],
    ])('RSA-%s should use algorithm %s', async (modulus, expectedAlgorithm) => {
      const { publicKey } = await generateRsaKeyPair({ modulus });

      const rdata = await generateTxtRdata(publicKey, TTL_OVERRIDE);

      const algorithmId = splitAndGetField(rdata, 0);
      expect(algorithmId).toStrictEqual(expectedAlgorithm.toString());
    });

    test('Unsupported RSA modulus should be refused', async () => {
      const algorithm = getAlgorithmParameters('RSA-PSS', 'generateKey');
      const modulusLength = 1024;
      const publicKey = await generatePublicKey({
        ...(algorithm.algorithm as RsaHashedKeyAlgorithm),
        modulusLength,
      });

      await expect(async () =>
        generateTxtRdata(publicKey, TTL_OVERRIDE),
      ).rejects.toThrowWithMessage(
        VeraError,
        `RSA key with modulus ${modulusLength} is unsupported`,
      );
    });
  });

  describe('Key id and type', () => {
    test('SHA-256 should be used by default with RSA keys', async () => {
      const rdata = await generateTxtRdata(rsaPublicKey, TTL_OVERRIDE);

      const actualKeyIdType = splitAndGetField(rdata, 1);
      expect(actualKeyIdType).toStrictEqual(KeyIdType.SHA256.toString());
      const actualKeyId = splitAndGetField(rdata, 2);
      const digest = calculateDigest('sha256', await derSerializePublicKey(rsaPublicKey));
      expect(actualKeyId).toStrictEqual(digest.toString('base64'));
    });

    test.each<[string, KeyIdType]>([
      ['sha256', KeyIdType.SHA256],
      ['sha384', KeyIdType.SHA384],
      ['sha512', KeyIdType.SHA512],
    ])('%s id type should be allowed for RSA keys', async (hashAlgo, keyIdType) => {
      const rdata = await generateTxtRdata(rsaPublicKey, TTL_OVERRIDE, { keyIdType });

      const actualKeyIdType = splitAndGetField(rdata, 1);
      expect(actualKeyIdType).toStrictEqual(keyIdType.toString());
      const actualKeyId = splitAndGetField(rdata, 2);
      const digest = calculateDigest(hashAlgo, await derSerializePublicKey(rsaPublicKey));
      expect(actualKeyId).toStrictEqual(digest.toString('base64'));
    });

    test('Unsupported type should be refused', async () => {
      const invalidKeyIdType = -1 as unknown as KeyIdType;
      await expect(
        generateTxtRdata(rsaPublicKey, TTL_OVERRIDE, { keyIdType: invalidKeyIdType }),
      ).rejects.toThrowWithMessage(VeraError, `Unsupported key id type (${invalidKeyIdType})`);
    });
  });

  describe('TTL override', () => {
    test('Negative values should be refused', async () => {
      const invalidTtlOverride = -1;
      await expect(async () =>
        generateTxtRdata(rsaPublicKey, invalidTtlOverride),
      ).rejects.toThrowWithMessage(
        VeraError,
        `TTL override must not be negative (got ${invalidTtlOverride})`,
      );
    });

    test('Zero should be allowed', async () => {
      const rdata = await generateTxtRdata(rsaPublicKey, 0);

      const ttl = splitAndGetField(rdata, 3);
      expect(ttl).toBe('0');
    });

    test('Positive values should be allowed', async () => {
      const ttlOverride = 1;
      const rdata = await generateTxtRdata(rsaPublicKey, ttlOverride);

      const ttl = splitAndGetField(rdata, 3);
      expect(ttl).toBe(ttlOverride.toString());
    });

    test('90 days should be allowed', async () => {
      const ttlOverride = secondsInDay * 90;
      const rdata = await generateTxtRdata(rsaPublicKey, ttlOverride);

      const ttl = splitAndGetField(rdata, 3);
      expect(ttl).toBe(ttlOverride.toString());
    });

    test('More than 90 days should be refused', async () => {
      const invalidTtlOverride = secondsInDay * 90 + 1;
      await expect(generateTxtRdata(rsaPublicKey, invalidTtlOverride)).rejects.toThrowWithMessage(
        VeraError,
        `TTL override must not exceed 90 days (got ${invalidTtlOverride} seconds)`,
      );
    });
  });

  describe('Service', () => {
    test('No service should be specified by default', async () => {
      const rdata = await generateTxtRdata(rsaPublicKey, TTL_OVERRIDE);

      const service = splitAndGetField(rdata, 4);
      expect(service).toBeUndefined();
    });

    test('Service should be specified if set', async () => {
      const serviceOid = '1.2.3.4.5';
      const rdata = await generateTxtRdata(rsaPublicKey, TTL_OVERRIDE, { serviceOid });

      const service = splitAndGetField(rdata, 4);
      expect(service).toStrictEqual(serviceOid);
    });
  });

  test('Non-RSA keys should be refused', async () => {
    const algorithmName = 'ECDSA';
    const publicKey = await generatePublicKey({ name: algorithmName, namedCurve: 'P-256' });

    await expect(async () => generateTxtRdata(publicKey, TTL_OVERRIDE)).rejects.toThrowWithMessage(
      VeraError,
      `Only RSA-PSS keys are supported (got ${algorithmName})`,
    );
  });
});
