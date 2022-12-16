import { jest } from '@jest/globals';
import { RsaPssProvider, type CryptoKey as WebCryptoKey } from 'webcrypto-core';

export class MockRsaPssProvider extends RsaPssProvider {
  public override readonly onGenerateKey = jest.fn<() => Promise<CryptoKeyPair>>();

  public override readonly onSign = jest.fn<() => Promise<ArrayBuffer>>();

  public override readonly onVerify = jest.fn<() => Promise<boolean>>();

  public override readonly onExportKey = jest.fn<() => Promise<ArrayBuffer | JsonWebKey>>();

  public override readonly onImportKey = jest.fn<() => Promise<WebCryptoKey>>();
}
