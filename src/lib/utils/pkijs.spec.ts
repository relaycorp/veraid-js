import { Crypto } from '@peculiar/webcrypto';
import { CryptoEngine, getEngine, setEngine } from 'pkijs';

import { getPkijsCrypto } from './pkijs.js';

const originalEngine = getEngine();
beforeEach(() => {
  setEngine(originalEngine.name, originalEngine.crypto!);
});

describe('getPkijsCrypto', () => {
  test('It should pass on the crypto object it got', () => {
    const stubEngine = new CryptoEngine({ crypto: new Crypto() });
    setEngine(stubEngine.name, stubEngine);

    const crypto = getPkijsCrypto();

    expect(crypto).toBe(stubEngine);
  });

  test('It should error out if there is no crypto object', () => {
    setEngine(originalEngine.name, undefined);

    expect(getPkijsCrypto).toThrow('PKI.js crypto engine is undefined');
  });
});
