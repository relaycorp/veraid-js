import { Crypto as BaseCrypto } from '@peculiar/webcrypto';
import { RsaPssProvider } from './RsaPssProvider.js';
export class VeraCrypto extends BaseCrypto {
    constructor(additionalProviders = []) {
        super();
        const { providers } = this.subtle;
        additionalProviders.forEach((provider) => {
            providers.set(provider);
        });
        const originalRsaPssProvider = providers.get('RSA-PSS');
        const newRsaPssProvider = new RsaPssProvider(originalRsaPssProvider);
        providers.set(newRsaPssProvider);
    }
}
//# sourceMappingURL=VeraCrypto.js.map