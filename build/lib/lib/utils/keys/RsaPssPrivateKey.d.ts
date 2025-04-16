import type { KeyUsages, ProviderCrypto } from 'webcrypto-core';
import type { HashingAlgorithm } from '../algorithms.js';
import { PrivateKey } from './PrivateKey.js';
export declare class RsaPssPrivateKey extends PrivateKey {
    readonly usages: KeyUsages;
    constructor(hashingAlgorithm: HashingAlgorithm, provider: ProviderCrypto);
}
