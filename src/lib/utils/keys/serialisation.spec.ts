import { jest } from '@jest/globals';
import { CryptoEngine } from 'pkijs';

import { MockRsaPssProvider } from '../../../testUtils/webcrypto/MockRsaPssProvider.js';
import { arrayBufferFrom } from '../../../testUtils/buffers.js';
import { bufferToArray } from '../buffers.js';

import {
  derDeserializeRsaPrivateKey,
  derDeserializeRsaPublicKey,
  derSerializePrivateKey,
  derSerializePublicKey,
} from './serialisation.js';
import { RsaPssPrivateKey } from './RsaPssPrivateKey.js';
import { generateRsaKeyPair } from './generation.js';

const STUB_KEY_PAIR = await generateRsaKeyPair();

describe('Key serializers', () => {
  const stubExportedKeyDer = arrayBufferFrom('Hey');
  const mockExportKey = jest.spyOn(CryptoEngine.prototype, 'exportKey');
  beforeEach(() => {
    mockExportKey.mockReset();
    mockExportKey.mockResolvedValue(stubExportedKeyDer);
  });

  afterAll(() => {
    mockExportKey.mockRestore();
  });

  describe('derSerializePublicKey', () => {
    test('Public key should be converted to buffer', async () => {
      const publicKeyDer = await derSerializePublicKey(STUB_KEY_PAIR.publicKey);

      expect(publicKeyDer).toStrictEqual(Buffer.from(stubExportedKeyDer));

      expect(mockExportKey).toHaveBeenCalledTimes(1);
      expect(mockExportKey).toHaveBeenCalledWith('spki', STUB_KEY_PAIR.publicKey);
    });

    test('Public key should be extracted first if input is PrivateKey', async () => {
      const provider = new MockRsaPssProvider();
      provider.onExportKey.mockResolvedValue(stubExportedKeyDer);
      const privateKey = new RsaPssPrivateKey('SHA-256', provider);

      await expect(derSerializePublicKey(privateKey)).resolves.toStrictEqual(
        Buffer.from(stubExportedKeyDer),
      );

      expect(mockExportKey).not.toHaveBeenCalled();
    });
  });

  describe('derSerializePrivateKey', () => {
    test('derSerializePrivateKey should convert private key to buffer', async () => {
      const privateKeyDer = await derSerializePrivateKey(STUB_KEY_PAIR.privateKey);

      expect(privateKeyDer).toStrictEqual(Buffer.from(stubExportedKeyDer));

      expect(mockExportKey).toHaveBeenCalledTimes(1);
      expect(mockExportKey).toHaveBeenCalledWith('pkcs8', STUB_KEY_PAIR.privateKey);
    });
  });
});

describe('Key deserializers', () => {
  const stubKeyDer = Buffer.from('Hey');
  const rsaAlgorithmOptions: RsaHashedImportParams = { name: 'RSA-PSS', hash: { name: 'SHA-256' } };

  const mockImportKey = jest.spyOn(CryptoEngine.prototype, 'importKey');
  beforeEach(() => {
    mockImportKey.mockClear();
  });

  afterAll(() => {
    mockImportKey.mockRestore();
  });

  test('derDeserializeRsaPublicKey should convert DER public key to RSA key', async () => {
    mockImportKey.mockResolvedValueOnce(STUB_KEY_PAIR.publicKey);

    const publicKey = await derDeserializeRsaPublicKey(stubKeyDer, rsaAlgorithmOptions);

    expect(publicKey).toBe(STUB_KEY_PAIR.publicKey);
    expect(mockImportKey).toHaveBeenCalledTimes(1);
    expect(mockImportKey).toHaveBeenCalledWith(
      'spki',
      bufferToArray(stubKeyDer),
      rsaAlgorithmOptions,
      true,
      ['verify'],
    );
  });

  test('derDeserializeRsaPublicKey should default to RSA-PSS with SHA-256', async () => {
    mockImportKey.mockResolvedValueOnce(STUB_KEY_PAIR.publicKey);

    const publicKey = await derDeserializeRsaPublicKey(stubKeyDer);

    expect(publicKey).toBe(STUB_KEY_PAIR.publicKey);
    expect(mockImportKey).toHaveBeenCalledTimes(1);
    expect(mockImportKey).toHaveBeenCalledWith(
      'spki',
      bufferToArray(stubKeyDer),
      rsaAlgorithmOptions,
      true,
      ['verify'],
    );
  });

  test('derDeserializeRsaPublicKey should accept an ArrayBuffer serialization', async () => {
    mockImportKey.mockResolvedValueOnce(STUB_KEY_PAIR.publicKey);

    const keyDerArrayBuffer = arrayBufferFrom(stubKeyDer);
    const publicKey = await derDeserializeRsaPublicKey(keyDerArrayBuffer, rsaAlgorithmOptions);

    expect(publicKey).toBe(STUB_KEY_PAIR.publicKey);
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
    mockImportKey.mockResolvedValueOnce(STUB_KEY_PAIR.privateKey);

    const privateKey = await derDeserializeRsaPrivateKey(stubKeyDer, rsaAlgorithmOptions);

    expect(privateKey).toBe(STUB_KEY_PAIR.privateKey);
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
    mockImportKey.mockResolvedValueOnce(STUB_KEY_PAIR.privateKey);

    const privateKey = await derDeserializeRsaPrivateKey(stubKeyDer);

    expect(privateKey).toBe(STUB_KEY_PAIR.privateKey);
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
