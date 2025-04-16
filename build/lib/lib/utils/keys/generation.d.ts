import type { HashingAlgorithm, RsaModulus } from '../algorithms.js';
export interface RsaKeyGenOptions {
    readonly modulus: RsaModulus;
    readonly hashingAlgorithm: HashingAlgorithm;
}
/**
 * Generate an RSA-PSS key pair.
 * @param options The RSA key generation options
 * @throws Error If the modulus or the hashing algorithm is disallowed.
 */
export declare function generateRsaKeyPair(options?: Partial<RsaKeyGenOptions>): Promise<CryptoKeyPair>;
export declare function getRsaPublicKeyFromPrivate(privateKey: CryptoKey): Promise<CryptoKey>;
