import { IssuerAndSerialNumber, SignedData as PkijsSignedData } from 'pkijs';
import { Certificate } from '../x509/Certificate.js';
import type { SignedDataSignatureOptions } from './SignedDataSignatureOptions.js';
export declare class SignedData {
    readonly pkijsSignedData: PkijsSignedData;
    private static reDeserialize;
    static deserialize(signedDataSerialized: ArrayBuffer): SignedData;
    /**
     * Create a CMS SignedData value for the specified plaintext.
     * @param plaintext - The plaintext to be signed
     * @param privateKey - The private key to sign with
     * @param signerCertificate - The certificate corresponding to the private key
     * @param attachedCertificates - The certificates to attach to the SignedData (empty by default)
     *                               The signer certificate is NOT automatically attached.
     * @param options - Additional options for the signature
     * @returns The SignedData object
     * @throws {CmsError} If the hashing algorithm is unsupported
     */
    static sign(plaintext: ArrayBuffer, privateKey: CryptoKey, signerCertificate: Certificate, attachedCertificates?: readonly Certificate[], options?: Partial<SignedDataSignatureOptions>): Promise<SignedData>;
    constructor(pkijsSignedData: PkijsSignedData);
    /**
     * The signed plaintext, if it was encapsulated.
     */
    get plaintext(): ArrayBuffer | null;
    /**
     * The signer's certificate, if it was encapsulated.
     */
    get signerCertificate(): Certificate | null;
    /**
     * The signer's issuer and serial number, if available.
     */
    get signerIssuerAndSerialNumber(): IssuerAndSerialNumber | null;
    /**
     * Set of encapsulated certificates.
     */
    get certificates(): Set<Certificate>;
    getSignedAttribute(type: string): any[] | null;
    serialize(): ArrayBuffer;
    verify(expectedPlaintext?: ArrayBuffer, signerCertificate?: Certificate): Promise<void>;
}
