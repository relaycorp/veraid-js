import { RsaPssProvider, type SubtleCrypto } from 'webcrypto-core';

import { MockRsaPssProvider } from '../../../testUtils/webcrypto/MockRsaPssProvider.js';

import { VeraCrypto } from './VeraCrypto.js';

describe('Constructor', () => {
  test('Additional providers should be optional', () => {
    const crypto = new VeraCrypto();

    expect((crypto.subtle as SubtleCrypto).providers.get('RSA-PSS')).toBeInstanceOf(RsaPssProvider);
  });

  test('Custom providers should be registered if set', () => {
    const providerName = 'COOL-PROVIDER';
    const customProvider = new (class extends MockRsaPssProvider {
      public override readonly name = providerName as any;
    })();
    const crypto = new VeraCrypto([customProvider]);

    expect((crypto.subtle as SubtleCrypto).providers.get(providerName)).toBe(customProvider);
  });
});
