import { beforeEach, jest } from '@jest/globals';
import { AesKwProvider, type SubtleCrypto } from 'webcrypto-core';

import { MockAesKwProvider } from '../../../testUtils/webcrypto/MockAesKwProvider.js';

import { AwalaAesKwProvider } from './AwalaAesKwProvider.js';

const mockGetCiphers = jest.fn<() => string[]>();
jest.unstable_mockModule('node:crypto', () => ({
  getCiphers: mockGetCiphers,
}));

// eslint-disable-next-line node/no-unsupported-features/es-syntax
const veraCrypto = await import('./VeraCrypto.js');

const CIPHERS: readonly string[] = [
  'aes-128-cbc',
  'aes-128-cfb',
  'aes-128-ctr',
  'aes-128-ecb',
  'aes-128-gcm',
  'aes-128-ofb',
];
beforeEach(() => {
  mockGetCiphers.mockReset();
  mockGetCiphers.mockReturnValue(CIPHERS as string[]);
});

describe('Constructor', () => {
  test("Pure JavaScript AES-KW provider should be used if Node doesn't support cipher", () => {
    const crypto = new veraCrypto.VeraCrypto();

    const aesKwProvider = (crypto.subtle as SubtleCrypto).providers.get('AES-KW');
    expect(aesKwProvider).toBeInstanceOf(AwalaAesKwProvider);
  });

  test('Node.js AES-KW provider should be used if Node supports cipher', () => {
    mockGetCiphers.mockReturnValue([...CIPHERS, 'id-aes128-wrap']);

    const crypto = new veraCrypto.VeraCrypto();

    const aesKwProvider = (crypto.subtle as SubtleCrypto).providers.get('AES-KW');
    expect(aesKwProvider).toBeInstanceOf(AesKwProvider);
    expect(aesKwProvider).not.toBeInstanceOf(AwalaAesKwProvider);
  });

  test('Custom providers should be registered', () => {
    const providerName = 'COOL-PROVIDER';
    const customProvider = new (class extends MockAesKwProvider {
      public override readonly name = providerName as any;
    })();
    const crypto = new veraCrypto.VeraCrypto([customProvider]);

    expect((crypto.subtle as SubtleCrypto).providers.get(providerName)).toBe(customProvider);
  });
});
