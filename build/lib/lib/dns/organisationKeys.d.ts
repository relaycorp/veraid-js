import { KeyAlgorithmType } from './KeyAlgorithmType.js';
export interface OrganisationKeySpec {
    readonly keyAlgorithm: KeyAlgorithmType;
    readonly keyId: string;
}
export declare function getKeySpec(publicKey: CryptoKey): Promise<OrganisationKeySpec>;
