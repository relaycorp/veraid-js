import { CryptoEngine } from 'pkijs';
import type { CryptoKeyWithProvider } from '../keys/CryptoKeyWithProvider.js';
/**
 * Generate and cache PKI.js engine for specified private key.
 */
export declare function getEngineForPrivateKey(privateKey: CryptoKey | CryptoKeyWithProvider): CryptoEngine;
