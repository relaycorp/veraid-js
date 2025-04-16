import { CryptoKey as WebCryptoKey, } from 'webcrypto-core';
export class PrivateKey extends WebCryptoKey {
    constructor(algorithm, provider) {
        super();
        this.algorithm = algorithm;
        this.provider = provider;
        this.extractable = true; // The **public** key is extractable as SPKI
        this.type = 'private';
    }
}
//# sourceMappingURL=PrivateKey.js.map