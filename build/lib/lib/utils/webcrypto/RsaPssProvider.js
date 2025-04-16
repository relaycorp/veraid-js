import { RSA_PKCS1_PSS_PADDING } from 'node:constants';
import { createVerify } from 'node:crypto';
import { RsaPssProvider as BaseRsaPssProvider } from 'webcrypto-core';
function getCryptoAlgorithm(alg) {
    switch (alg.hash.name.toUpperCase()) {
        case 'SHA-256': {
            return 'RSA-SHA256';
        }
        case 'SHA-384': {
            return 'RSA-SHA384';
        }
        case 'SHA-512': {
            return 'RSA-SHA512';
        }
        default: {
            throw new Error(`Unrecognised or unsupported hash algorithm (${alg.hash.name})`);
        }
    }
}
export class RsaPssProvider extends BaseRsaPssProvider {
    constructor(originalProvider) {
        super();
        this.originalProvider = originalProvider;
    }
    async onVerify(_algorithm, key, signature, data) {
        const cryptoAlg = getCryptoAlgorithm(key.algorithm);
        const signer = createVerify(cryptoAlg);
        signer.update(Buffer.from(data));
        const keyDer = (await this.exportKey('spki', key));
        const keyPem = Buffer.from(keyDer).toString('base64');
        const options = {
            key: `-----BEGIN PUBLIC KEY-----\n${keyPem}\n-----END PUBLIC KEY-----`,
            padding: RSA_PKCS1_PSS_PADDING,
        };
        return signer.verify(options, new Uint8Array(signature));
    }
    async onSign(algorithm, key, data, ...args) {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
        return this.originalProvider.onSign(algorithm, key, data, ...args);
    }
    async onGenerateKey(algorithm, isExtractable, keyUsages, ...args) {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
        return this.originalProvider.onGenerateKey(algorithm, isExtractable, keyUsages, ...args);
    }
    async onExportKey(format, key, ...args) {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
        return this.originalProvider.onExportKey(format, key, ...args);
    }
    async onImportKey(format, keyData, algorithm, isExtractable, keyUsages, ...args) {
        return this.originalProvider.onImportKey(format, keyData, algorithm, isExtractable, keyUsages, 
        // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
        ...args);
    }
}
//# sourceMappingURL=RsaPssProvider.js.map