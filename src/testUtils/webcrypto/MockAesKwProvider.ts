import { jest } from '@jest/globals';
import { AesKwProvider, type CryptoKey as WebCryptoKey } from 'webcrypto-core';

export class MockAesKwProvider extends AesKwProvider {
  public override readonly onGenerateKey = jest.fn<() => Promise<WebCryptoKey>>();

  public override readonly onExportKey = jest.fn<() => Promise<ArrayBuffer | JsonWebKey>>();

  public override readonly onImportKey = jest.fn<() => Promise<WebCryptoKey>>();
}
