import { BmpString, Integer, OctetString } from 'asn1js';
import { min, setMilliseconds } from 'date-fns';
import { AsnParser, AsnSerializer } from '@peculiar/asn1-schema';
import { Certificate as CertificateSchema } from '@peculiar/asn1-x509';
import { AttributeTypeAndValue, AuthorityKeyIdentifier, BasicConstraints, Certificate as PkijsCertificate, CertificateChainValidationEngine, Extension, } from 'pkijs';
import { getEngineForPrivateKey } from '../webcrypto/engine.js';
import { AUTHORITY_KEY, BASIC_CONSTRAINTS, COMMON_NAME, SUBJECT_KEY } from '../../oids.js';
import { derDeserialize } from '../asn1.js';
import { generateRandom64BitValue } from '../crypto.js';
import { NODE_ENGINE } from '../pkijs.js';
import { getPublicKeyDigest } from '../keys/digest.js';
import { DatePeriod } from '../../dates.js';
import CertificateError from './CertificateError.js';
const X509_CERTIFICATE_VERSION_3 = 2;
const SIGNED_INTEGER_MAX_OCTET = 127;
function generatePositiveAsn1Integer() {
    const potentiallySignedInteger = new Uint8Array(generateRandom64BitValue());
    // ASN.1 BER/DER INTEGER uses two's complement with big endian, so we ensure the integer is
    // positive by keeping the leftmost octet below 128.
    const positiveInteger = new Uint8Array(potentiallySignedInteger);
    positiveInteger.set([Math.min(potentiallySignedInteger[0], SIGNED_INTEGER_MAX_OCTET)], 0);
    return new Integer({ valueHex: positiveInteger });
}
function makeBasicConstraintsExtension(isCa, pathLengthConstraint) {
    if (pathLengthConstraint < 0) {
        throw new CertificateError(`pathLenConstraint must be >= 0 (got ${pathLengthConstraint})`);
    }
    const basicConstraints = new BasicConstraints({
        cA: isCa,
        pathLenConstraint: pathLengthConstraint,
    });
    return new Extension({
        critical: true,
        // eslint-disable-next-line @typescript-eslint/naming-convention
        extnID: BASIC_CONSTRAINTS,
        extnValue: basicConstraints.toSchema().toBER(false),
    });
}
async function makeAuthorityKeyIdExtension(publicKey) {
    const keyDigest = await getPublicKeyDigest(publicKey);
    const keyIdEncoded = new OctetString({ valueHex: keyDigest });
    return new Extension({
        // eslint-disable-next-line @typescript-eslint/naming-convention
        extnID: AUTHORITY_KEY,
        extnValue: new AuthorityKeyIdentifier({ keyIdentifier: keyIdEncoded }).toSchema().toBER(false),
    });
}
async function makeSubjectKeyIdExtension(publicKey) {
    const keyDigest = await getPublicKeyDigest(publicKey);
    return new Extension({
        // eslint-disable-next-line @typescript-eslint/naming-convention
        extnID: SUBJECT_KEY,
        extnValue: new OctetString({ valueHex: keyDigest }).toBER(false),
    });
}
function cloneAsn1jsValue(value) {
    const valueSerialized = value.toBER(false);
    return derDeserialize(valueSerialized);
}
/**
 * X.509 Certificate.
 *
 * This is a high-level class on top of PKI.js Certificate, to make the use of VeraId
 * certificates easy and safe.
 */
export class Certificate {
    static validateIssuerCertificate(issuerCertificate) {
        const extensions = issuerCertificate.pkijsCertificate.extensions ?? [];
        const bcExtension = extensions.find((extension) => extension.extnID === BASIC_CONSTRAINTS);
        if (bcExtension === undefined) {
            throw new CertificateError('Basic constraints extension is missing from issuer certificate');
        }
        const basicConstraintsAsn1 = derDeserialize(bcExtension.extnValue.valueBlock.valueHexView);
        const basicConstraints = new BasicConstraints({ schema: basicConstraintsAsn1 });
        if (!basicConstraints.cA) {
            throw new CertificateError('Issuer is not a CA');
        }
    }
    /**
     * Deserialize certificate from DER-encoded value.
     * @param certDer DER-encoded X.509 certificate
     */
    static deserialize(certDer) {
        const asn1Value = derDeserialize(certDer);
        const pkijsCert = new PkijsCertificate({ schema: asn1Value });
        return new Certificate(pkijsCert);
    }
    /**
     * Create a Certificate instance from an ASN.1 schema
     * @internal
     * @param schema - The ASN.1 schema representation of a certificate
     */
    static fromSchema(schema) {
        const certDer = AsnSerializer.serialize(schema);
        return Certificate.deserialize(certDer);
    }
    /**
     * Issue a VeraId PKI certificate.
     * @internal
     */
    static async issue(options) {
        // PKI.js should round down to the nearest second per X.509. We should do it ourselves to
        // avoid discrepancies when the validity dates of a freshly-issued certificate are used.
        const validityStartDate = setMilliseconds(options.validityStartDate ?? new Date(), 0);
        const validityEndDate = setMilliseconds(options.issuerCertificate
            ? min([options.issuerCertificate.validityPeriod.end, options.validityEndDate])
            : options.validityEndDate, 0);
        if (options.issuerCertificate) {
            Certificate.validateIssuerCertificate(options.issuerCertificate);
        }
        const issuerPublicKey = options.issuerCertificate
            ? await options.issuerCertificate.pkijsCertificate.getPublicKey(undefined, NODE_ENGINE)
            : options.subjectPublicKey;
        const pkijsCert = new PkijsCertificate({
            extensions: [
                makeBasicConstraintsExtension(Boolean(options.isCa), options.pathLenConstraint ?? 0),
                await makeAuthorityKeyIdExtension(issuerPublicKey),
                await makeSubjectKeyIdExtension(options.subjectPublicKey),
            ],
            serialNumber: generatePositiveAsn1Integer(),
            version: X509_CERTIFICATE_VERSION_3,
        });
        pkijsCert.notBefore.value = validityStartDate;
        pkijsCert.notAfter.value = validityEndDate;
        pkijsCert.subject.typesAndValues.push(new AttributeTypeAndValue({
            type: COMMON_NAME,
            value: new BmpString({ value: options.commonName }),
        }));
        const issuerDn = options.issuerCertificate
            ? options.issuerCertificate.pkijsCertificate.subject.typesAndValues
            : pkijsCert.subject.typesAndValues;
        pkijsCert.issuer.typesAndValues = issuerDn.map((attribute) => new AttributeTypeAndValue({
            type: attribute.type,
            value: cloneAsn1jsValue(attribute.value),
        }));
        await pkijsCert.subjectPublicKeyInfo.importKey(options.subjectPublicKey, NODE_ENGINE);
        const signatureHashAlgo = options.issuerPrivateKey.algorithm
            .hash;
        const engine = getEngineForPrivateKey(options.issuerPrivateKey);
        await pkijsCert.sign(options.issuerPrivateKey, signatureHashAlgo.name, engine);
        return new Certificate(pkijsCert);
    }
    constructor(pkijsCertificate) {
        this.pkijsCertificate = pkijsCertificate;
        this.pkijsCertificate = pkijsCertificate;
        this.validityPeriod = DatePeriod.init(pkijsCertificate.notBefore.value, pkijsCertificate.notAfter.value);
    }
    /**
     * Return serial number.
     *
     * This doesn't return a `number` or `BigInt` because the serial number could require more than
     * 8 octets (which is the maximum number of octets required to represent a 64-bit unsigned
     * integer).
     */
    get serialNumber() {
        const serialNumberBlock = this.pkijsCertificate.serialNumber;
        const serialNumber = serialNumberBlock.valueBlock.toBER();
        return Buffer.from(serialNumber);
    }
    get commonName() {
        const commonNameAttribute = this.pkijsCertificate.subject.typesAndValues.find((attribute) => attribute.type === COMMON_NAME);
        if (commonNameAttribute === undefined) {
            throw new CertificateError('Distinguished Name does not contain Common Name');
        }
        return commonNameAttribute.value.valueBlock.value;
    }
    /**
     * Serialize certificate as DER-encoded buffer.
     */
    serialize() {
        const certAsn1js = this.pkijsCertificate.toSchema(true);
        return certAsn1js.toBER(false);
    }
    /**
     * Convert a Certificate instance to its ASN.1 schema representation
     * @internal
     */
    toSchema() {
        const certDer = this.serialize();
        return AsnParser.parse(certDer, CertificateSchema);
    }
    /**
     * Report whether this certificate is the same as `otherCertificate`.
     */
    isEqual(otherCertificate) {
        const thisCertSerialized = Buffer.from(this.serialize());
        const otherCertSerialized = Buffer.from(otherCertificate.serialize());
        return thisCertSerialized.equals(otherCertSerialized);
    }
    /**
     * Checks if this certificate matches the given issuer and serial number.
     * @internal
     * @param issuerAndSerialNumber - The issuer and serial number to match against
     * @returns True if the certificate matches the issuer and serial number, false otherwise
     */
    matchesIssuerAndSerialNumber(issuerAndSerialNumber) {
        return (this.pkijsCertificate.issuer.isEqual(issuerAndSerialNumber.issuer) &&
            this.pkijsCertificate.serialNumber.isEqual(issuerAndSerialNumber.serialNumber));
    }
    /**
     * Get the subject public key.
     */
    async getPublicKey() {
        return this.pkijsCertificate.getPublicKey(undefined, NODE_ENGINE);
    }
    /**
     * Return the certification path (aka "certificate chain") if this certificate can be trusted.
     * @param intermediateCaCertificates The alleged chain for the certificate
     * @param trustedCertificates The collection of certificates that are actually trusted
     * @throws CertificateError when this certificate is not on a certificate path from a CA in
     *   `trustedCertificates`
     */
    async getCertificationPath(intermediateCaCertificates, trustedCertificates) {
        // Ignore any intermediate certificate that's also the issuer of a trusted certificate.
        // The main reason for doing this isn't performance, but the fact that PKI.js would fail to
        // compute the path.
        const intermediateCertsSanitized = intermediateCaCertificates.filter((certificate) => {
            for (const trustedCertificate of trustedCertificates) {
                if (trustedCertificate.pkijsCertificate.issuer.isEqual(certificate.pkijsCertificate.subject)) {
                    return false;
                }
            }
            return true;
        });
        const chainValidator = new CertificateChainValidationEngine({
            certs: [
                ...intermediateCertsSanitized.map((certificate) => certificate.pkijsCertificate),
                this.pkijsCertificate,
            ],
            trustedCerts: trustedCertificates.map((certificate) => certificate.pkijsCertificate),
        });
        const verification = await chainValidator.verify({ passedWhenNotRevValues: false }, NODE_ENGINE);
        if (!verification.result) {
            throw new CertificateError(verification.resultMessage);
        }
        return verification.certificatePath.map((pkijsCert) => new Certificate(pkijsCert));
    }
}
//# sourceMappingURL=Certificate.js.map