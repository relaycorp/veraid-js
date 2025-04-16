import { PrivateKey } from './PrivateKey.js';
export class RsaPssPrivateKey extends PrivateKey {
    constructor(hashingAlgorithm, provider) {
        const algorithm = { name: 'RSA-PSS', hash: { name: hashingAlgorithm } };
        super(algorithm, provider);
        this.usages = ['sign'];
    }
}
//# sourceMappingURL=RsaPssPrivateKey.js.map