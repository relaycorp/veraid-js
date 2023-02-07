import type { HashingAlgorithm } from '../algorithms.js';
import { MockRsaPssProvider } from '../../../testUtils/webcrypto/MockRsaPssProvider.js';

import { RsaPssPrivateKey } from './RsaPssPrivateKey.js';

const PROVIDER = new MockRsaPssProvider();

const HASHING_ALGORITHM: HashingAlgorithm = 'SHA-384';

describe('RsaPssPrivateKey', () => {
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
