import { type TrustAnchor } from '@relaycorp/dnssec';
import type { CryptoKey } from 'webcrypto-core';
import { SignatureBundle } from '../SignatureBundle.js';
import { MemberIdBundle } from '../memberIdBundle/MemberIdBundle.js';
import { OrganisationSigner } from '../OrganisationSigner.js';
import { DatePeriod } from '../dates.js';
import type { MockTrustChainOptions } from './MockTrustChainOptions.js';
/**
 * Mock trust chain for testing purposes
 */
export declare class MockTrustChain {
    readonly dnssecTrustAnchors: readonly TrustAnchor[];
    readonly chain: MemberIdBundle | OrganisationSigner;
    readonly signerPrivateKey: CryptoKey;
    readonly validityPeriod: DatePeriod;
    /**
     * Generate a mock trust chain
     * @param orgName - The name of the organisation
     * @param userName - The name of the user
     * @param expiryDate - The expiry date of the trust chain
     * @param options - The options for the mock trust chain
     * @returns A mock trust chain
     */
    static generate(orgName: string, userName: string | undefined, expiryDate: Date, options?: Partial<MockTrustChainOptions>): Promise<MockTrustChain>;
    protected constructor(dnssecTrustAnchors: readonly TrustAnchor[], chain: MemberIdBundle | OrganisationSigner, signerPrivateKey: CryptoKey, validityPeriod: DatePeriod);
    /**
     * Sign a plaintext with the chain
     * @param plaintext - The plaintext to sign
     * @param serviceOid - The service OID for which to sign the plaintext
     * @param shouldEncapsulatePlaintext - Whether to encapsulate the plaintext in the signature
     * @returns A signature bundle
     */
    sign(plaintext: ArrayBuffer, serviceOid: string, shouldEncapsulatePlaintext?: boolean): Promise<SignatureBundle>;
}
