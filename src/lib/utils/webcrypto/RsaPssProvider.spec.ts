import { Buffer } from 'node:buffer';
import { RSA_PKCS1_PSS_PADDING, RSA_PSS_SALTLEN_MAX_SIGN } from 'node:constants';
import { createSign } from 'node:crypto';

import { Crypto } from '@peculiar/webcrypto';
import type { CryptoKey } from 'webcrypto-core';

import { MockRsaPssProvider } from '../../../testUtils/webcrypto/MockRsaPssProvider.js';
import { generateRsaKeyPair } from '../keys/generation.js';
import type { HashingAlgorithm } from '../algorithms.js';

import { RsaPssProvider } from './RsaPssProvider.js';

const SUBTLE_CRYPTO = new Crypto().subtle;

const PLAINTEXT = new TextEncoder().encode('test data');

const RSA_PSS_SIGN_ALGORITHM: RsaPssParams = { name: 'RSA-PSS', saltLength: 32 };

async function sign(plaintext: ArrayBuffer, privateKey: CryptoKey): Promise<ArrayBuffer> {
  return SUBTLE_CRYPTO.sign(RSA_PSS_SIGN_ALGORITHM, privateKey, plaintext);
}

class OriginalRsaPssProvider extends MockRsaPssProvider {
  public constructor() {
    super();
    this.onExportKey.mockImplementation(async (format: KeyFormat, key: CryptoKey) =>
      SUBTLE_CRYPTO.exportKey(format, key),
    );
  }
}

describe('RsaPssProvider', () => {
  describe('verify', () => {
    describe('Hash functions', () => {
      test.each<HashingAlgorithm>(['SHA-256', 'SHA-384', 'SHA-512'])(
        'SHA-%s should be supported',
        async (hashingAlgorithm) => {
          const provider = new RsaPssProvider(new OriginalRsaPssProvider());
          const { privateKey, publicKey } = await generateRsaKeyPair({ hashingAlgorithm });
          const signature = await sign(PLAINTEXT, privateKey);

          await expect(
            provider.verify(RSA_PSS_SIGN_ALGORITHM, publicKey, signature, PLAINTEXT),
          ).resolves.toBeTrue();
        },
      );
    });

    test('invalid signature should not validate', async () => {
      const provider = new RsaPssProvider(new OriginalRsaPssProvider());
      const { publicKey } = await generateRsaKeyPair();
      const signature = new Uint8Array(256);
      crypto.getRandomValues(signature);

      await expect(
        provider.verify(RSA_PSS_SIGN_ALGORITHM, publicKey, signature, PLAINTEXT),
      ).resolves.toBeFalse();
    });

    test('valid signature with non-WebCrypto-compliant saltLength should validate', async () => {
      const provider = new RsaPssProvider(new OriginalRsaPssProvider());
      const { privateKey, publicKey } = await generateRsaKeyPair();
      const privateKeyDer = await SUBTLE_CRYPTO.exportKey('pkcs8', privateKey);

      const signer = createSign('SHA256');
      signer.update(Buffer.from(PLAINTEXT));
      const privateKeyPem = `-----BEGIN PRIVATE KEY-----\n${Buffer.from(privateKeyDer).toString(
        'base64',
      )}\n-----END PRIVATE KEY-----`;
      const signature = signer.sign({
        key: privateKeyPem,
        padding: RSA_PKCS1_PSS_PADDING,

        // Don't use a salt length of 32, which is what WebCrypto expects for SHA-256
        saltLength: RSA_PSS_SALTLEN_MAX_SIGN,
      });

      await expect(
        provider.verify(RSA_PSS_SIGN_ALGORITHM, publicKey, signature, PLAINTEXT),
      ).resolves.toBeTrue();
    });

    test('valid signature with WebCrypto-compliant saltLength should validate', async () => {
      const provider = new RsaPssProvider(new OriginalRsaPssProvider());
      const { privateKey, publicKey } = await generateRsaKeyPair();

      const signature = await sign(PLAINTEXT, privateKey);

      await expect(
        provider.verify(RSA_PSS_SIGN_ALGORITHM, publicKey, signature, PLAINTEXT),
      ).resolves.toBeTrue();
    });
  });

  describe('exportKey', () => {
    test('should call exportKey on original provider', async () => {
      const originalProvider = new OriginalRsaPssProvider();
      const provider = new RsaPssProvider(originalProvider);
      const format = 'spki';
      const { publicKey } = await generateRsaKeyPair();
      const exportedKey = new ArrayBuffer(8);
      originalProvider.onExportKey.mockResolvedValue(exportedKey);

      const result = await provider.exportKey(format, publicKey);

      expect(result).toBe(exportedKey);
      expect(originalProvider.onExportKey).toHaveBeenCalledWith(format, publicKey);
    });
  });

  describe('importKey', () => {
    test('should call importKey on original provider', async () => {
      const originalProvider = new OriginalRsaPssProvider();
      const provider = new RsaPssProvider(originalProvider);
      const format = 'spki';
      const keyData = new ArrayBuffer(8);
      const algorithm = { name: 'RSA-PSS', hash: { name: 'SHA-256' } };
      const isExtractable = true;
      const keyUsages = ['verify'] as KeyUsage[];
      const importedKey: CryptoKey = { type: 'public' } as unknown as CryptoKey;
      originalProvider.onImportKey.mockResolvedValue(importedKey);

      const result = await provider.importKey(format, keyData, algorithm, isExtractable, keyUsages);

      expect(result).toBe(importedKey);
      expect(originalProvider.onImportKey).toHaveBeenCalledWith(
        format,
        keyData,
        algorithm,
        isExtractable,
        keyUsages,
      );
    });
  });

  describe('sign', () => {
    test('should call sign on original provider', async () => {
      const originalProvider = new OriginalRsaPssProvider();
      const provider = new RsaPssProvider(originalProvider);
      const algorithm = { name: 'RSA-PSS', saltLength: 32 };
      const { privateKey } = await generateRsaKeyPair();
      const data = new ArrayBuffer(8);
      const signature = new ArrayBuffer(256);
      originalProvider.onSign.mockResolvedValue(signature);

      const result = await provider.sign(algorithm, privateKey, data);

      expect(result).toBe(signature);
      expect(originalProvider.onSign).toHaveBeenCalledWith(algorithm, privateKey, data);
    });
  });

  describe('generateKey', () => {
    test('should call generateKey on original provider', async () => {
      const originalProvider = new OriginalRsaPssProvider();
      const provider = new RsaPssProvider(originalProvider);
      const isExtractable = true;
      const keyUsages = ['sign', 'verify'] as KeyUsage[];
      const keyPair: CryptoKeyPair = { privateKey: {}, publicKey: {} } as unknown as CryptoKeyPair;
      const rsaKeyParams: RsaHashedKeyGenParams = {
        name: 'RSA-PSS',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: { name: 'SHA-256' },
      };

      originalProvider.onGenerateKey.mockResolvedValue(keyPair);

      const result = await provider.generateKey(rsaKeyParams, isExtractable, keyUsages);

      expect(result).toBe(keyPair);
      expect(originalProvider.onGenerateKey).toHaveBeenCalledWith(
        rsaKeyParams,
        isExtractable,
        keyUsages,
      );
    });
  });
});
