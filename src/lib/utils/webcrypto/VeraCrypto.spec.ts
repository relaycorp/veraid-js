import { RsaPssProvider as BaseRsaPssProvider, type SubtleCrypto } from 'webcrypto-core';

import { MockRsaPssProvider } from '../../../testUtils/webcrypto/MockRsaPssProvider.js';

import { VeraCrypto } from './VeraCrypto.js';
import { RsaPssProvider as CustomRsaPssProvider } from './RsaPssProvider.js';

describe('Constructor', () => {
  test('Additional providers should be optional', () => {
    const crypto = new VeraCrypto(false);

    expect((crypto.subtle as SubtleCrypto).providers.get('RSA-PSS')).toBeInstanceOf(
      BaseRsaPssProvider,
    );
  });

  test('Custom providers should be registered if set', () => {
    const providerName = 'COOL-PROVIDER';
    const customProvider = new (class extends MockRsaPssProvider {
      public override readonly name = providerName as any;
    })();
    const crypto = new VeraCrypto(false, [customProvider]);

    expect((crypto.subtle as SubtleCrypto).providers.get(providerName)).toBe(customProvider);
  });

  test('Custom RSA-PSS provider should not be used if disabled', () => {
    const crypto = new VeraCrypto(false);

    const provider = (crypto.subtle as SubtleCrypto).providers.get('RSA-PSS');
    expect(provider).toBeInstanceOf(BaseRsaPssProvider);
    expect(provider).not.toBeInstanceOf(CustomRsaPssProvider);
  });

  test('Custom RSA-PSS provider should be used if required', () => {
    const crypto = new VeraCrypto(true);

    const provider = (crypto.subtle as SubtleCrypto).providers.get('RSA-PSS');
    expect(provider).toBeInstanceOf(CustomRsaPssProvider);
  });
});
