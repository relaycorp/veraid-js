import { type KeyAlgorithm as WebCryptoKeyAlgorithm, type ProviderCrypto } from 'webcrypto-core';

import { MockAesKwProvider } from '../../testUtils/webcrypto/MockAesKwProvider.js';

import { type HashingAlgorithm } from './algorithms.js';
import { PrivateKey, RsaPssPrivateKey } from './PrivateKey.js';
import { AwalaAesKwProvider } from './webcrypto/AwalaAesKwProvider.js';

const PROVIDER = new AwalaAesKwProvider(new MockAesKwProvider());

describe('PrivateKey', () => {
  const ALGORITHM: KeyAlgorithm = { name: 'RSA-PSS' };

  class StubPrivateKey extends PrivateKey {
    public constructor(algorithm: WebCryptoKeyAlgorithm, provider: ProviderCrypto) {
      super(algorithm, provider);
    }
  }

  test('Key type should be private', () => {
    const key = new StubPrivateKey(ALGORITHM, PROVIDER);

    expect(key.type).toBe('private');
  });

  test('Key should be extractable', () => {
    const key = new StubPrivateKey(ALGORITHM, PROVIDER);

    expect(key.extractable).toBeTrue();
  });

  test('Algorithm should be honoured', () => {
    const key = new StubPrivateKey(ALGORITHM, PROVIDER);

    expect(key.algorithm).toStrictEqual(ALGORITHM);
  });

  test('Provider should be honoured', () => {
    const key = new StubPrivateKey(ALGORITHM, PROVIDER);

    expect(key.provider).toStrictEqual(PROVIDER);
  });
});

describe('RsaPssPrivateKey', () => {
  const HASHING_ALGORITHM: HashingAlgorithm = 'SHA-384';

  test('Key usages should only allow signing', () => {
    const key = new RsaPssPrivateKey(HASHING_ALGORITHM, PROVIDER);

    expect(key.usages).toStrictEqual(['sign']);
  });

  test('Hashing algorithm should be added to key algorithm', () => {
    const key = new RsaPssPrivateKey(HASHING_ALGORITHM, PROVIDER);

    expect(key.algorithm).toStrictEqual({
      hash: { name: HASHING_ALGORITHM },
      name: 'RSA-PSS',
    });
  });

  test('Provider should be honoured', () => {
    const key = new RsaPssPrivateKey(HASHING_ALGORITHM, PROVIDER);

    expect(key.provider).toStrictEqual(PROVIDER);
  });
});
