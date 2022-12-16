import { type SubtleCrypto } from 'webcrypto-core';

import { MockRsaPssProvider } from '../../../testUtils/webcrypto/MockRsaPssProvider.js';
import { RsaPssPrivateKey } from '../keys/RsaPssPrivateKey.js';

import { getEngineForPrivateKey } from './engine.js';

const PROVIDER = new MockRsaPssProvider();

describe('getEngine', () => {
  test('undefined should be returned if CryptoKey is used', () => {
    const engine = getEngineForPrivateKey(null as unknown as CryptoKey);

    expect(engine).toBeUndefined();
  });

  test('Nameless engine should be returned if PrivateKey is used', () => {
    const key = new RsaPssPrivateKey('SHA-256', PROVIDER);

    const engine = getEngineForPrivateKey(key);

    expect(engine?.name).toBeEmpty();
  });

  test('Engine crypto should use provider from private key', () => {
    const key = new RsaPssPrivateKey('SHA-256', PROVIDER);

    const engine = getEngineForPrivateKey(key);

    expect((engine?.crypto.subtle as SubtleCrypto).providers.get(PROVIDER.name)).toBe(PROVIDER);
  });

  test('Same engine should be returned if multiple keys share provider', () => {
    // This is to check engines are being cached
    const key1 = new RsaPssPrivateKey('SHA-256', PROVIDER);
    const key2 = new RsaPssPrivateKey('SHA-256', PROVIDER);

    const engine1 = getEngineForPrivateKey(key1);
    const engine2 = getEngineForPrivateKey(key2);

    expect(engine1).toBe(engine2);
  });

  test('Different engines should be returned if keys use different providers', () => {
    const key1 = new RsaPssPrivateKey('SHA-256', PROVIDER);
    const key2 = new RsaPssPrivateKey('SHA-256', new MockRsaPssProvider());

    const engine1 = getEngineForPrivateKey(key1);
    const engine2 = getEngineForPrivateKey(key2);

    expect(engine1).not.toBe(engine2);
  });
});
