import { CryptoKey as WebCryptoKey, type KeyAlgorithm as WebCryptoKeyAlgorithm, type ProviderCrypto } from 'webcrypto-core';
import type { CryptoKeyWithProvider } from './CryptoKeyWithProvider.js';
export declare abstract class PrivateKey extends WebCryptoKey implements CryptoKeyWithProvider {
    readonly algorithm: WebCryptoKeyAlgorithm;
    readonly provider: ProviderCrypto;
    readonly extractable = true;
    readonly type: KeyType;
    protected constructor(algorithm: WebCryptoKeyAlgorithm, provider: ProviderCrypto);
}
