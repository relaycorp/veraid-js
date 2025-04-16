import { RsaPssProvider } from 'webcrypto-core';
import { MockRsaPssProvider } from '../../../testUtils/webcrypto/MockRsaPssProvider.js';
import { VeraCrypto } from './VeraCrypto.js';
describe('Constructor', () => {
    test('Additional providers should be optional', () => {
        const crypto = new VeraCrypto();
        expect(crypto.subtle.providers.get('RSA-PSS')).toBeInstanceOf(RsaPssProvider);
    });
    test('Custom providers should be registered if set', () => {
        const providerName = 'COOL-PROVIDER';
        const customProvider = new (class extends MockRsaPssProvider {
            constructor() {
                super(...arguments);
                this.name = providerName;
            }
        })();
        const crypto = new VeraCrypto([customProvider]);
        expect(crypto.subtle.providers.get(providerName)).toBe(customProvider);
    });
});
//# sourceMappingURL=VeraCrypto.spec.js.map