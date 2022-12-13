import { createHash } from 'node:crypto';

import bufferToArray from 'buffer-to-arraybuffer';
import { CryptoEngine } from 'pkijs';

import { arrayBufferFrom, sha256Hex } from '../_test_utils.js';
import { MockRsaPssProvider } from '../../testUtils/webcrypto/MockRsaPssProvider.js';

import { type HashingAlgorithm, type RSAModulus } from './algorithms.js';
import {
  derDeserializeRSAPrivateKey,
  derDeserializeRSAPublicKey,
  derSerializePrivateKey,
  derSerializePublicKey,
  generateRSAKeyPair,
  getIdFromIdentityKey,
  getPublicKeyDigest,
  getPublicKeyDigestHex,
  getRSAPublicKeyFromPrivate,
} from './keys.js';
import { RsaPssPrivateKey } from './PrivateKey.js';

describe('generateRsaKeyPair', () => {
  test('Keys should be RSA-PSS', async () => {
    const keyPair = await generateRSAKeyPair();

    expect(keyPair.publicKey.algorithm.name).toBe('RSA-PSS');
    expect(keyPair.privateKey.algorithm.name).toBe('RSA-PSS');
  });

  test('Keys should be extractable', async () => {
    const keyPair = await generateRSAKeyPair();

    expect(keyPair.publicKey.extractable).toBe(true);
    expect(keyPair.privateKey.extractable).toBe(true);
  });

  test('Key usages should be used for signatures only', async () => {
    const keyPair = await generateRSAKeyPair();

    expect(keyPair).toHaveProperty('publicKey.usages', ['verify']);
    expect(keyPair).toHaveProperty('privateKey.usages', ['sign']);
  });

  describe('Modulus', () => {
    test('Default modulus should be 2048', async () => {
      const keyPair = await generateRSAKeyPair();
      expect(keyPair.publicKey.algorithm).toHaveProperty('modulusLength', 2048);
      expect(keyPair.privateKey.algorithm).toHaveProperty('modulusLength', 2048);
    });

    test.each([2048, 3072, 4096] as readonly RSAModulus[])(
      'Modulus %s should be used if explicitly requested',
      async () => {
        const modulus = 4096;
        const keyPair = await generateRSAKeyPair({ modulus });
        expect(keyPair.publicKey.algorithm).toHaveProperty('modulusLength', modulus);
        expect(keyPair.privateKey.algorithm).toHaveProperty('modulusLength', modulus);
      },
    );

    test('Modulus < 2048 should not supported', async () => {
      await expect(generateRSAKeyPair({ modulus: 1024 } as any)).rejects.toThrow(
        'RSA modulus must be => 2048 per RS-018 (got 1024)',
      );
    });
  });

  describe('Hashing algorithm', () => {
    test('SHA-256 should be used by default', async () => {
      const keyPair = await generateRSAKeyPair();
      expect(keyPair.publicKey.algorithm).toHaveProperty('hash.name', 'SHA-256');
      expect(keyPair.privateKey.algorithm).toHaveProperty('hash.name', 'SHA-256');
    });

    test.each(['SHA-384', 'SHA-512'] as readonly HashingAlgorithm[])(
      '%s hashing should be supported',
      async (hashingAlgorithm) => {
        const keyPair = await generateRSAKeyPair({ hashingAlgorithm });
        expect(keyPair.publicKey.algorithm).toHaveProperty('hash.name', hashingAlgorithm);
        expect(keyPair.privateKey.algorithm).toHaveProperty('hash.name', hashingAlgorithm);
      },
    );

    test('SHA-1 should not be supported', async () => {
      await expect(generateRSAKeyPair({ hashingAlgorithm: 'SHA-1' } as any)).rejects.toThrow(
        'SHA-1 is disallowed by RS-018',
      );
    });
  });
});

describe('getRSAPublicKeyFromPrivate', () => {
  test('Public key should be returned', async () => {
    const keyPair = await generateRSAKeyPair();

    const publicKey = await getRSAPublicKeyFromPrivate(keyPair.privateKey);

    // It's important to check we got a public key before checking its serialisation. If we try to
    // serialise a private key with SPKI, it'd internally use the public key first.
    expect(publicKey.type).toEqual(keyPair.publicKey.type);
    await expect(derSerializePublicKey(publicKey)).resolves.toEqual(
      await derSerializePublicKey(keyPair.publicKey),
    );
  });

  test('Public key should be taken from provider if custom one is used', async () => {
    const keyPair = await generateRSAKeyPair();
    const mockRsaPssProvider = new MockRsaPssProvider();
    mockRsaPssProvider.onExportKey.mockResolvedValue(
      await derSerializePublicKey(keyPair.publicKey),
    );
    const privateKey = new RsaPssPrivateKey('SHA-256', mockRsaPssProvider);

    const publicKey = await getRSAPublicKeyFromPrivate(privateKey);

    await expect(derSerializePublicKey(publicKey)).resolves.toEqual(
      await derSerializePublicKey(keyPair.publicKey),
    );
  });

  test('Public key should honour algorithm parameters', async () => {
    const keyPair = await generateRSAKeyPair();

    const publicKey = await getRSAPublicKeyFromPrivate(keyPair.privateKey);

    expect(publicKey.algorithm).toEqual(keyPair.publicKey.algorithm);
  });

  test('Public key should only be used to verify signatures', async () => {
    const keyPair = await generateRSAKeyPair();

    const publicKey = await getRSAPublicKeyFromPrivate(keyPair.privateKey);

    expect(publicKey.usages).toEqual(['verify']);
  });
});

describe('Key serializers', () => {
  let stubKeyPair: CryptoKeyPair;
  beforeAll(async () => {
    stubKeyPair = await generateRSAKeyPair();
  });

  const stubExportedKeyDer = arrayBufferFrom('Hey');
  const mockExportKey = jest.spyOn(CryptoEngine.prototype, 'exportKey');
  beforeEach(async () => {
    mockExportKey.mockReset();
    mockExportKey.mockResolvedValue(stubExportedKeyDer);
  });

  afterAll(() => {
    mockExportKey.mockRestore();
  });

  describe('derSerializePublicKey', () => {
    test('Public key should be converted to buffer', async () => {
      const publicKeyDer = await derSerializePublicKey(stubKeyPair.publicKey);

      expect(publicKeyDer).toEqual(Buffer.from(stubExportedKeyDer));

      expect(mockExportKey).toHaveBeenCalledTimes(1);
      expect(mockExportKey).toHaveBeenCalledWith('spki', stubKeyPair.publicKey);
    });

    test('Public key should be extracted first if input is PrivateKey', async () => {
      const provider = new MockRsaPssProvider();
      provider.onExportKey.mockResolvedValue(stubExportedKeyDer);
      const privateKey = new RsaPssPrivateKey('SHA-256', provider);

      await expect(derSerializePublicKey(privateKey)).resolves.toEqual(
        Buffer.from(stubExportedKeyDer),
      );

      expect(mockExportKey).not.toHaveBeenCalled();
    });
  });

  describe('derSerializePrivateKey', () => {
    test('derSerializePrivateKey should convert private key to buffer', async () => {
      const privateKeyDer = await derSerializePrivateKey(stubKeyPair.privateKey);

      expect(privateKeyDer).toEqual(Buffer.from(stubExportedKeyDer));

      expect(mockExportKey).toHaveBeenCalledTimes(1);
      expect(mockExportKey).toHaveBeenCalledWith('pkcs8', stubKeyPair.privateKey);
    });
  });
});

describe('Key deserializers', () => {
  const stubKeyDer = Buffer.from('Hey');
  const rsaAlgorithmOptions: RsaHashedImportParams = { name: 'RSA-PSS', hash: { name: 'SHA-256' } };

  let stubKeyPair: CryptoKeyPair;
  beforeAll(async () => {
    stubKeyPair = await generateRSAKeyPair();
  });
  const mockImportKey = jest.spyOn(CryptoEngine.prototype, 'importKey');
  beforeEach(async () => {
    mockImportKey.mockClear();
  });

  afterAll(() => {
    mockImportKey.mockRestore();
  });

  test('derDeserializeRSAPublicKey should convert DER public key to RSA key', async () => {
    mockImportKey.mockResolvedValueOnce(stubKeyPair.publicKey);

    const publicKey = await derDeserializeRSAPublicKey(stubKeyDer, rsaAlgorithmOptions);

    expect(publicKey).toBe(stubKeyPair.publicKey);
    expect(mockImportKey).toHaveBeenCalledTimes(1);
    expect(mockImportKey).toHaveBeenCalledWith(
      'spki',
      bufferToArray(stubKeyDer),
      rsaAlgorithmOptions,
      true,
      ['verify'],
    );
  });

  test('derDeserializeRSAPublicKey should default to RSA-PSS with SHA-256', async () => {
    mockImportKey.mockResolvedValueOnce(stubKeyPair.publicKey);

    const publicKey = await derDeserializeRSAPublicKey(stubKeyDer);

    expect(publicKey).toBe(stubKeyPair.publicKey);
    expect(mockImportKey).toHaveBeenCalledTimes(1);
    expect(mockImportKey).toHaveBeenCalledWith(
      'spki',
      bufferToArray(stubKeyDer),
      rsaAlgorithmOptions,
      true,
      ['verify'],
    );
  });

  test('derDeserializeRSAPublicKey should accept an ArrayBuffer serialization', async () => {
    mockImportKey.mockResolvedValueOnce(stubKeyPair.publicKey);

    const keyDerArrayBuffer = arrayBufferFrom(stubKeyDer);
    const publicKey = await derDeserializeRSAPublicKey(keyDerArrayBuffer, rsaAlgorithmOptions);

    expect(publicKey).toBe(stubKeyPair.publicKey);
    expect(mockImportKey).toHaveBeenCalledTimes(1);
    expect(mockImportKey).toHaveBeenCalledWith(
      'spki',
      keyDerArrayBuffer,
      rsaAlgorithmOptions,
      true,
      ['verify'],
    );
  });

  test('derDeserializeRSAPrivateKey should convert DER private key to RSA key', async () => {
    mockImportKey.mockResolvedValueOnce(stubKeyPair.privateKey);

    const privateKey = await derDeserializeRSAPrivateKey(stubKeyDer, rsaAlgorithmOptions);

    expect(privateKey).toBe(stubKeyPair.privateKey);
    expect(mockImportKey).toHaveBeenCalledTimes(1);
    expect(mockImportKey).toHaveBeenCalledWith(
      'pkcs8',
      bufferToArray(stubKeyDer),
      rsaAlgorithmOptions,
      true,
      ['sign'],
    );
  });

  test('derDeserializeRSAPrivateKey should default to RSA-PSS with SHA-256', async () => {
    mockImportKey.mockResolvedValueOnce(stubKeyPair.privateKey);

    const privateKey = await derDeserializeRSAPrivateKey(stubKeyDer);

    expect(privateKey).toBe(stubKeyPair.privateKey);
    expect(mockImportKey).toHaveBeenCalledTimes(1);
    expect(mockImportKey).toHaveBeenCalledWith(
      'pkcs8',
      bufferToArray(stubKeyDer),
      rsaAlgorithmOptions,
      true,
      ['sign'],
    );
  });
});

describe('getPublicKeyDigest', () => {
  test('SHA-256 digest should be returned in hex', async () => {
    const keyPair = await generateRSAKeyPair();

    const digest = await getPublicKeyDigest(keyPair.publicKey);

    expect(Buffer.from(digest)).toEqual(
      createHash('sha256')
        .update(await derSerializePublicKey(keyPair.publicKey))
        .digest(),
    );
  });

  test('Public key should be extracted first if input is private key', async () => {
    const mockPublicKeySerialized = arrayBufferFrom('the public key');
    const provider = new MockRsaPssProvider();
    provider.onExportKey.mockResolvedValue(mockPublicKeySerialized);
    const privateKey = new RsaPssPrivateKey('SHA-256', provider);

    const digest = await getPublicKeyDigest(privateKey);

    expect(Buffer.from(digest)).toEqual(
      createHash('sha256').update(Buffer.from(mockPublicKeySerialized)).digest(),
    );
  });
});

test('getPublicKeyDigestHex should return the SHA-256 hex digest of the public key', async () => {
  const keyPair = await generateRSAKeyPair();

  const digestHex = await getPublicKeyDigestHex(keyPair.publicKey);

  expect(digestHex).toEqual(sha256Hex(await derSerializePublicKey(keyPair.publicKey)));
});

describe('getIdFromIdentityKey', () => {
  test('Id should be computed from identity key', async () => {
    const keyPair = await generateRSAKeyPair();

    const id = await getIdFromIdentityKey(keyPair.publicKey);

    expect(id).toBe(`0${sha256Hex(await derSerializePublicKey(keyPair.publicKey))}`);
  });
});
