import { Crypto as BaseCrypto } from '@peculiar/webcrypto';
import type { ProviderCrypto } from 'webcrypto-core';
export declare class VeraCrypto extends BaseCrypto {
    constructor(additionalProviders?: readonly ProviderCrypto[]);
}
