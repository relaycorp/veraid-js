import { MockRsaPssProvider } from '../../../testUtils/webcrypto/MockRsaPssProvider.js';
import { type HashingAlgorithm, type RsaModulus } from '../algorithms.js';

import {
  generateRsaKeyPair,
  getRsaPublicKeyFromPrivate,
  type RsaKeyGenOptions,
} from './generation.js';
import { derSerializePublicKey } from './serialisation.js';
import { RsaPssPrivateKey } from './RsaPssPrivateKey.js';

describe('generateRsaKeyPair', () => {
  test('Keys should be RSA-PSS', async () => {
    const keyPair = await generateRsaKeyPair();

    expect(keyPair.publicKey.algorithm.name).toBe('RSA-PSS');
    expect(keyPair.privateKey.algorithm.name).toBe('RSA-PSS');
  });

  test('Keys should be extractable', async () => {
    const keyPair = await generateRsaKeyPair();

    expect(keyPair.publicKey.extractable).toBe(true);
    expect(keyPair.privateKey.extractable).toBe(true);
  });

  test('Key usages should be used for signatures only', async () => {
    const keyPair = await generateRsaKeyPair();

    expect(keyPair).toHaveProperty('publicKey.usages', ['verify']);
    expect(keyPair).toHaveProperty('privateKey.usages', ['sign']);
  });

  describe('Modulus', () => {
    test('Default modulus should be 2048', async () => {
      const keyPair = await generateRsaKeyPair();
      expect(keyPair.publicKey.algorithm).toHaveProperty('modulusLength', 2048);
      expect(keyPair.privateKey.algorithm).toHaveProperty('modulusLength', 2048);
    });

    test.each([2048, 3072, 4096] as readonly RsaModulus[])(
      'Modulus %s should be used if explicitly requested',
      async () => {
        const modulus = 4096;
        const keyPair = await generateRsaKeyPair({ modulus });
        expect(keyPair.publicKey.algorithm).toHaveProperty('modulusLength', modulus);
        expect(keyPair.privateKey.algorithm).toHaveProperty('modulusLength', modulus);
      },
    );

    test('Modulus < 2048 should not supported', async () => {
      await expect(
        generateRsaKeyPair({ modulus: 1024 } as unknown as RsaKeyGenOptions),
      ).rejects.toThrow('RSA modulus must be => 2048 (got 1024)');
    });
  });

  describe('Hashing algorithm', () => {
    test('SHA-256 should be used by default', async () => {
      const keyPair = await generateRsaKeyPair();
      expect(keyPair.publicKey.algorithm).toHaveProperty('hash.name', 'SHA-256');
      expect(keyPair.privateKey.algorithm).toHaveProperty('hash.name', 'SHA-256');
    });

    test.each(['SHA-384', 'SHA-512'] as readonly HashingAlgorithm[])(
      '%s hashing should be supported',
      async (hashingAlgorithm) => {
        const keyPair = await generateRsaKeyPair({ hashingAlgorithm });
        expect(keyPair.publicKey.algorithm).toHaveProperty('hash.name', hashingAlgorithm);
        expect(keyPair.privateKey.algorithm).toHaveProperty('hash.name', hashingAlgorithm);
      },
    );

    test('SHA-1 should not be supported', async () => {
      await expect(
        generateRsaKeyPair({ hashingAlgorithm: 'SHA-1' } as unknown as RsaKeyGenOptions),
      ).rejects.toThrow('SHA-1 is unsupported');
    });
  });
});

describe('getRsaPublicKeyFromPrivate', () => {
  test('Public key should be returned', async () => {
    const keyPair = await generateRsaKeyPair();

    const publicKey = await getRsaPublicKeyFromPrivate(keyPair.privateKey);

    // It's important to check we got a public key before checking its serialisation. If we try to
    // serialise a private key with SPKI, it'd internally use the public key first.
    expect(publicKey.type).toStrictEqual(keyPair.publicKey.type);
    await expect(derSerializePublicKey(publicKey)).resolves.toStrictEqual(
      await derSerializePublicKey(keyPair.publicKey),
    );
  });

  test('Public key should be taken from provider if custom one is used', async () => {
    const keyPair = await generateRsaKeyPair();
    const mockRsaPssProvider = new MockRsaPssProvider();
    mockRsaPssProvider.onExportKey.mockResolvedValue(
      await derSerializePublicKey(keyPair.publicKey),
    );
    const privateKey = new RsaPssPrivateKey('SHA-256', mockRsaPssProvider);

    const publicKey = await getRsaPublicKeyFromPrivate(privateKey);

    await expect(derSerializePublicKey(publicKey)).resolves.toStrictEqual(
      await derSerializePublicKey(keyPair.publicKey),
    );
  });

  test('Public key should honour algorithm parameters', async () => {
    const keyPair = await generateRsaKeyPair();

    const publicKey = await getRsaPublicKeyFromPrivate(keyPair.privateKey);

    expect(publicKey.algorithm).toStrictEqual(keyPair.publicKey.algorithm);
  });

  test('Public key should only be used to verify signatures', async () => {
    const keyPair = await generateRsaKeyPair();

    const publicKey = await getRsaPublicKeyFromPrivate(keyPair.privateKey);

    expect(publicKey.usages).toStrictEqual(['verify']);
  });
});
