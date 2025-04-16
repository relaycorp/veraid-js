import { ContentInfo } from '@peculiar/asn1-cms';
import type { TrustAnchor } from '@relaycorp/dnssec';
import type { SignatureOptions } from './SignatureOptions.js';
import { Certificate } from './utils/x509/Certificate.js';
import { MemberIdBundle } from './memberIdBundle/MemberIdBundle.js';
import { type IDatePeriod } from './dates.js';
import type { SignatureBundleVerification } from './SignatureBundleVerification.js';
import { OrganisationSigner } from './OrganisationSigner.js';
import { VeraidDnssecChain } from './dns/VeraidDnssecChain.js';
export declare class SignatureBundle {
    readonly dnssecChain: VeraidDnssecChain;
    readonly orgCertificate: Certificate;
    readonly signature: ContentInfo;
    /**
     * Deserialise a binary representation into a SignatureBundle instance
     * @param serialisation - The serialised signature bundle
     * @returns A new SignatureBundle instance
     * @throws {VeraidError} If the version is not 0
     */
    static deserialise(serialisation: ArrayBuffer): SignatureBundle;
    /**
     * Create a signature for the specified plaintext
     * @param plaintext - The data to sign
     * @param serviceOid - The OID of the service for which the signature is created
     * @param signer - The member id bundle or organisation signer to use for signing
     * @param signingKey - The private key corresponding to the signer certificate
     * @param expiryDate - The date when the signature expires
     * @param options - Additional options for signature creation
     * @param options.startDate - The date when the signature becomes valid (defaults to now)
     * @param options.shouldEncapsulatePlaintext - Whether to include the plaintext in the signature (defaults to false)
     * @returns A new SignatureBundle instance
     */
    static sign(plaintext: ArrayBuffer, serviceOid: string, signer: MemberIdBundle | OrganisationSigner, signingKey: CryptoKey, expiryDate: Date, options?: Partial<SignatureOptions>): Promise<SignatureBundle>;
    constructor(dnssecChain: VeraidDnssecChain, orgCertificate: Certificate, signature: ContentInfo);
    /**
     * Serialise this signature bundle to its binary representation
     * @returns The serialised signature bundle
     */
    serialise(): ArrayBuffer;
    private buildVerificationChain;
    private verifySignature;
    /**
     * Verify the signature against the specified plaintext
     * @param plaintext - The plaintext to verify (can be undefined if the plaintext is encapsulated in the signature)
     * @param serviceOid - The OID of the service for which the signature should be valid
     * @param dateOrPeriod - The date or period for which the signature should be valid (defaults to now)
     * @param trustAnchors - The DNSSEC trust anchors to use for verification
     * @returns The verification result containing the plaintext and member information
     * @throws {VeraidError} If the signature is invalid
     */
    verify(plaintext: ArrayBuffer | undefined, serviceOid: string, dateOrPeriod?: Date | IDatePeriod, trustAnchors?: readonly TrustAnchor[]): Promise<SignatureBundleVerification>;
}
