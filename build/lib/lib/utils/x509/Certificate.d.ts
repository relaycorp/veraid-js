import { Certificate as PkijsCertificate } from 'pkijs';
import { DatePeriod } from '../../dates.js';
/**
 * X.509 Certificate.
 *
 * This is a high-level class on top of PKI.js Certificate, to make the use of VeraId
 * certificates easy and safe.
 */
export declare class Certificate {
    readonly pkijsCertificate: PkijsCertificate;
    protected static validateIssuerCertificate(issuerCertificate: Certificate): void;
    /**
     * Deserialize certificate from DER-encoded value.
     * @param certDer DER-encoded X.509 certificate
     */
    static deserialize(certDer: ArrayBuffer): Certificate;
    readonly validityPeriod: DatePeriod;
    constructor(pkijsCertificate: PkijsCertificate);
    /**
     * Return serial number.
     *
     * This doesn't return a `number` or `BigInt` because the serial number could require more than
     * 8 octets (which is the maximum number of octets required to represent a 64-bit unsigned
     * integer).
     */
    get serialNumber(): Buffer;
    get commonName(): string;
    /**
     * Serialize certificate as DER-encoded buffer.
     */
    serialize(): ArrayBuffer;
    /**
     * Report whether this certificate is the same as `otherCertificate`.
     */
    isEqual(otherCertificate: Certificate): boolean;
    /**
     * Get the subject public key.
     */
    getPublicKey(): Promise<CryptoKey>;
    /**
     * Return the certification path (aka "certificate chain") if this certificate can be trusted.
     * @param intermediateCaCertificates The alleged chain for the certificate
     * @param trustedCertificates The collection of certificates that are actually trusted
     * @throws CertificateError when this certificate is not on a certificate path from a CA in
     *   `trustedCertificates`
     */
    getCertificationPath(intermediateCaCertificates: readonly Certificate[], trustedCertificates: readonly Certificate[]): Promise<readonly Certificate[]>;
}
