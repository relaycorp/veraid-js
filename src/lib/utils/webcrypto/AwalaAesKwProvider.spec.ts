import { Crypto } from '@peculiar/webcrypto';
import bufferToArray from 'buffer-to-arraybuffer';
import { type AesKwProvider, type SubtleCrypto } from 'webcrypto-core';

import { MockAesKwProvider } from '../../../testUtils/webcrypto/MockAesKwProvider.js';
import { arrayBufferFrom } from '../../../testUtils/buffers.js';

import { AwalaAesKwProvider } from './AwalaAesKwProvider.js';

const nodejsCrypto = new Crypto();
const nodejsAesKwProvider = (nodejsCrypto.subtle as SubtleCrypto).providers.get(
  'AES-KW',
) as AesKwProvider;

const algorithm: AesKeyGenParams = { name: 'AES-KW', length: 128 };

const keyUsages: KeyUsage[] = ['wrapKey', 'unwrapKey'];

let cryptoKey: CryptoKey;
beforeAll(async () => {
  cryptoKey = await nodejsCrypto.subtle.generateKey(algorithm, true, keyUsages);
});

const unwrappedKeySerialized = bufferToArray(
  Buffer.from('00112233445566778899AABBCCDDEEFF', 'hex'),
);

describe('onGenerateKey', () => {
  test('Method should proxy original provider', async () => {
    const originalProvider = new MockAesKwProvider();
    originalProvider.onGenerateKey.mockResolvedValue(cryptoKey);
    const provider = new AwalaAesKwProvider(originalProvider);

    const generatedKey = await provider.onGenerateKey(algorithm, true, keyUsages);

    expect(generatedKey).toBe(cryptoKey);
    expect(originalProvider.onGenerateKey).toHaveBeenCalledWith(algorithm, true, keyUsages);
  });
});

describe('onExportKey', () => {
  test('Method should proxy original provider', async () => {
    const cryptoKeySerialized = arrayBufferFrom('this is the key, serialized');
    const originalProvider = new MockAesKwProvider();
    originalProvider.onExportKey.mockResolvedValue(cryptoKeySerialized);
    const provider = new AwalaAesKwProvider(originalProvider);
    const keyFormat = 'raw';

    const exportedKey = await provider.onExportKey(keyFormat, cryptoKey);

    expect(exportedKey).toBe(cryptoKeySerialized);
    expect(originalProvider.onExportKey).toHaveBeenCalledWith(keyFormat, cryptoKey);
  });
});

describe('onImportKey', () => {
  test('Method should proxy original provider', async () => {
    const originalProvider = new MockAesKwProvider();
    originalProvider.onImportKey.mockResolvedValue(cryptoKey);
    const provider = new AwalaAesKwProvider(originalProvider);
    const keyFormat = 'raw';
    const cryptoKeySerialized = arrayBufferFrom('this is the key, serialized');

    const exportedKey = await provider.onImportKey(
      keyFormat,
      cryptoKeySerialized,
      algorithm,
      true,
      keyUsages,
    );

    expect(exportedKey).toBe(cryptoKey);
    expect(originalProvider.onImportKey).toHaveBeenCalledWith(
      keyFormat,
      cryptoKeySerialized,
      algorithm,
      true,
      keyUsages,
    );
  });
});

describe('onEncrypt', () => {
  test('Ciphertext should be decryptable with Node.js', async () => {
    const provider = new AwalaAesKwProvider(nodejsAesKwProvider);

    const wrappedKey = await provider.onEncrypt(algorithm, cryptoKey, unwrappedKeySerialized);

    const unwrappedKey = await nodejsCrypto.subtle.unwrapKey(
      'raw',
      wrappedKey,
      cryptoKey,
      algorithm,
      algorithm,
      true,
      keyUsages,
    );
    await expect(nodejsAesKwProvider.exportKey('raw', unwrappedKey)).resolves.toStrictEqual(
      unwrappedKeySerialized,
    );
  });
});

describe('onDecrypt', () => {
  test('Ciphertext produced with Node.js should be decryptable', async () => {
    const provider = new AwalaAesKwProvider(nodejsAesKwProvider);
    const nodejsWrappedKey = await nodejsAesKwProvider.onEncrypt(
      algorithm,
      cryptoKey,
      unwrappedKeySerialized,
    );

    const unwrappedKey = await provider.onDecrypt(algorithm, cryptoKey, nodejsWrappedKey);

    expect(unwrappedKey).toStrictEqual(unwrappedKeySerialized);
  });
});
