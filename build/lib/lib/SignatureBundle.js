import { ContentInfo } from '@peculiar/asn1-cms';
import { AsnParser, AsnSerializer } from '@peculiar/asn1-schema';
import { Attribute } from 'pkijs';
import { Utf8String } from 'asn1js';
import { SignatureBundleSchema } from './schemas/SignatureBundleSchema.js';
import { SignatureMetadataSchema } from './schemas/SignatureMetadataSchema.js';
import { DatePeriodSchema } from './schemas/DatePeriodSchema.js';
import { VERAID_OIDS } from './oids.js';
import { derDeserialize } from './utils/asn1.js';
import { SignedData } from './utils/cms/SignedData.js';
import { Certificate } from './utils/x509/Certificate.js';
import { VeraidError } from './VeraidError.js';
import { MemberIdBundle } from './memberIdBundle/MemberIdBundle.js';
import { DatePeriod } from './dates.js';
import { BOT_NAME } from './pki/member.js';
import { OrganisationSigner } from './OrganisationSigner.js';
import { VeraidDnssecChain } from './dns/VeraidDnssecChain.js';
function generateMetadata(serviceOid, startDate, expiryDate) {
    if (expiryDate < startDate) {
        throw new VeraidError('Signature start date cannot be after expiry date');
    }
    const metadataSchema = new SignatureMetadataSchema();
    metadataSchema.serviceOid = serviceOid;
    const datePeriod = new DatePeriodSchema();
    datePeriod.start = startDate;
    datePeriod.end = expiryDate;
    metadataSchema.validityPeriod = datePeriod;
    const serialisation = AsnSerializer.serialize(metadataSchema);
    return derDeserialize(serialisation);
}
async function generateSignedData(options) {
    const { plaintext, signerCertificate, signingKey, serviceOid, shouldEncapsulatePlaintext = false, expiryDate, startDate, attributedMemberName, shouldIncludeSignerCertificate, } = options;
    const metadataSchema = generateMetadata(serviceOid, startDate ?? new Date(), expiryDate);
    const metadataAttribute = new Attribute({
        type: VERAID_OIDS.SIGNATURE_METADATA_ATTR,
        values: [metadataSchema],
    });
    const extraSignedAttrs = [metadataAttribute];
    if (attributedMemberName !== undefined) {
        const memberAttributionAttribute = new Attribute({
            type: VERAID_OIDS.MEMBER_ATTRIBUTION_ATTR,
            values: [attributedMemberName],
        });
        extraSignedAttrs.push(memberAttributionAttribute);
    }
    const signedData = await SignedData.sign(plaintext, signingKey, signerCertificate, shouldIncludeSignerCertificate ? [signerCertificate] : [], {
        extraSignedAttrs,
        shouldEncapsulatePlaintext,
    });
    return AsnParser.parse(signedData.serialize(), ContentInfo);
}
function getMetadata(signedData) {
    const metadataAttributeAsn1 = signedData.getSignedAttribute(VERAID_OIDS.SIGNATURE_METADATA_ATTR);
    if (!metadataAttributeAsn1) {
        throw new VeraidError('Signature metadata is missing');
    }
    let metadata;
    try {
        metadata = AsnParser.parse(metadataAttributeAsn1[0].toBER(), SignatureMetadataSchema);
    }
    catch {
        throw new VeraidError('Signature metadata is malformed');
    }
    if (metadata.validityPeriod.end < metadata.validityPeriod.start) {
        throw new VeraidError('Signature validity period ends before it starts');
    }
    return metadata;
}
function convertDatePeriod(dateOrPeriod) {
    if (dateOrPeriod instanceof Date) {
        return DatePeriod.init(dateOrPeriod, dateOrPeriod);
    }
    if (dateOrPeriod.end < dateOrPeriod.start) {
        throw new VeraidError('Verification expiry date cannot be before start date');
    }
    return DatePeriod.init(dateOrPeriod.start, dateOrPeriod.end);
}
function getSignaturePeriodIntersection(metadata, dateOrPeriod) {
    const signaturePeriod = DatePeriod.init(metadata.validityPeriod.start, metadata.validityPeriod.end);
    const verificationPeriod = convertDatePeriod(dateOrPeriod);
    const signaturePeriodIntersection = verificationPeriod.intersect(signaturePeriod);
    if (!signaturePeriodIntersection) {
        throw new VeraidError(`Signature period (${signaturePeriod.toString()}) ` +
            `does not overlap with required period (${verificationPeriod.toString()})`);
    }
    return signaturePeriodIntersection;
}
export class SignatureBundle {
    /**
     * Deserialise a binary representation into a SignatureBundle instance
     * @param serialisation - The serialised signature bundle
     * @returns A new SignatureBundle instance
     * @throws {VeraidError} If the version is not 0
     */
    static deserialise(serialisation) {
        const bundleSchema = AsnParser.parse(serialisation, SignatureBundleSchema);
        if (bundleSchema.version !== 0) {
            throw new VeraidError('Unsupported SignatureBundle version');
        }
        const orgCertificate = Certificate.fromSchema(bundleSchema.organisationCertificate);
        const dnssecChain = new VeraidDnssecChain(orgCertificate.commonName, bundleSchema.dnssecChain);
        return new SignatureBundle(dnssecChain, orgCertificate, bundleSchema.signature);
    }
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
    static async sign(plaintext, serviceOid, signer, signingKey, expiryDate, options = {}) {
        let signerCertificate;
        let attributedMemberName;
        let shouldIncludeSignerCertificate;
        if (signer instanceof MemberIdBundle) {
            // It's a member signature bundle
            signerCertificate = signer.memberCertificate;
            attributedMemberName = undefined;
            shouldIncludeSignerCertificate = true;
        }
        else {
            // It's an organisation signature bundle
            signerCertificate = signer.orgCertificate;
            attributedMemberName = new Utf8String({
                value: signer.attributedMemberName ?? BOT_NAME,
            });
            shouldIncludeSignerCertificate = false;
        }
        const signedData = await generateSignedData({
            plaintext,
            signerCertificate,
            signingKey,
            serviceOid,
            expiryDate,
            attributedMemberName,
            shouldIncludeSignerCertificate,
            ...options,
        });
        return new SignatureBundle(signer.dnssecChain, signer.orgCertificate, signedData);
    }
    constructor(dnssecChain, orgCertificate, signature) {
        this.dnssecChain = dnssecChain;
        this.orgCertificate = orgCertificate;
        this.signature = signature;
    }
    /**
     * Serialise this signature bundle to its binary representation
     * @returns The serialised signature bundle
     */
    serialise() {
        const signatureSchema = new SignatureBundleSchema();
        signatureSchema.version = 0;
        signatureSchema.dnssecChain = this.dnssecChain.toSchema();
        signatureSchema.organisationCertificate = this.orgCertificate.toSchema();
        signatureSchema.signature = this.signature;
        return AsnSerializer.serialize(signatureSchema);
    }
    buildVerificationChain(signedData) {
        const memberAttributionAttr = signedData.getSignedAttribute(VERAID_OIDS.MEMBER_ATTRIBUTION_ATTR);
        let chain;
        if (memberAttributionAttr) {
            // It's an organisation signature
            const [memberAttribution] = memberAttributionAttr;
            if (!(memberAttribution instanceof Utf8String)) {
                throw new VeraidError('Member attribution attribute is malformed');
            }
            const memberAttributionValue = memberAttribution.getValue();
            chain = new OrganisationSigner(this.dnssecChain, this.orgCertificate, memberAttributionValue === BOT_NAME ? undefined : memberAttributionValue);
        }
        else {
            // It's a member signature
            if (!signedData.signerCertificate) {
                throw new VeraidError('Member signature is missing signer certificate');
            }
            const { signerCertificate } = signedData;
            chain = new MemberIdBundle(this.dnssecChain, this.orgCertificate, signerCertificate);
        }
        return chain;
    }
    async verifySignature(signedData, plaintext, serviceOid, dateOrPeriod, chain) {
        const signerCertificate = chain instanceof MemberIdBundle ? undefined : this.orgCertificate;
        try {
            await signedData.verify(plaintext, signerCertificate);
        }
        catch (err) {
            throw new VeraidError('Signature is invalid', { cause: err });
        }
        const metadata = getMetadata(signedData);
        if (metadata.serviceOid !== serviceOid) {
            throw new VeraidError(`Signature is bound to a different service (${metadata.serviceOid})`);
        }
        return getSignaturePeriodIntersection(metadata, dateOrPeriod);
    }
    /**
     * Verify the signature against the specified plaintext
     * @param plaintext - The plaintext to verify (can be undefined if the plaintext is encapsulated in the signature)
     * @param serviceOid - The OID of the service for which the signature should be valid
     * @param dateOrPeriod - The date or period for which the signature should be valid (defaults to now)
     * @param trustAnchors - The DNSSEC trust anchors to use for verification
     * @returns The verification result containing the plaintext and member information
     * @throws {VeraidError} If the signature is invalid
     */
    async verify(plaintext, serviceOid, dateOrPeriod = new Date(), trustAnchors) {
        const signedData = SignedData.deserialize(AsnSerializer.serialize(this.signature));
        const chain = this.buildVerificationChain(signedData);
        const signaturePeriodIntersection = await this.verifySignature(signedData, plaintext, serviceOid, dateOrPeriod, chain);
        let member;
        try {
            member = await chain.verify(serviceOid, signaturePeriodIntersection, trustAnchors);
        }
        catch (err) {
            throw new VeraidError('Chain verification failed', { cause: err });
        }
        return {
            plaintext: plaintext ?? signedData.plaintext,
            member,
            wasSignedByMember: chain instanceof MemberIdBundle,
        };
    }
}
//# sourceMappingURL=SignatureBundle.js.map