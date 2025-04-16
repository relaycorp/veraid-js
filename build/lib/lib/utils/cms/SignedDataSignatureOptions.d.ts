import type { Attribute } from 'pkijs';
import type { HashingAlgorithm } from '../algorithms.js';
export interface SignedDataSignatureOptions {
    readonly hashingAlgorithmName: HashingAlgorithm;
    readonly shouldEncapsulatePlaintext: boolean;
    readonly extraSignedAttrs: readonly Attribute[];
}
