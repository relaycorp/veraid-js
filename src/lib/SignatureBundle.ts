import { ContentInfo } from '@peculiar/asn1-cms';
import { Certificate as CertificateSchema } from '@peculiar/asn1-x509';
import { AsnParser, AsnSerializer } from '@peculiar/asn1-schema';
import { Attribute } from 'pkijs';
import { type Sequence, type BaseBlock, Utf8String } from 'asn1js';
import type { TrustAnchor } from '@relaycorp/dnssec';

import type { DnssecChainSchema } from './schemas/DnssecChainSchema.js';
import { SignatureBundleSchema } from './schemas/SignatureBundleSchema.js';
import { SignatureMetadataSchema } from './schemas/SignatureMetadataSchema.js';
import { DatePeriodSchema } from './schemas/DatePeriodSchema.js';
import { VERAID_OIDS } from './oids.js';
import { derDeserialize } from './utils/asn1.js';
import { SignedData } from './utils/cms/SignedData.js';
import type { SignatureOptions } from './SignatureOptions.js';
import Certificate from './utils/x509/Certificate.js';
import VeraidError from './VeraidError.js';
import {
  MemberIdBundle as MemberIdBundleClass,
  type MemberIdBundle,
} from './memberIdBundle/MemberIdBundle.js';
import { DatePeriod, type IDatePeriod } from './dates.js';
import type { SignatureBundleVerification } from './SignatureBundleVerification.js';
import { BOT_NAME } from './pki/member.js';
import type { OrganisationSigner } from './OrganisationSigner.js';

function generateMetadata(serviceOid: string, startDate: Date, expiryDate: Date): Sequence {
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
  return derDeserialize(serialisation) as Sequence;
}

interface SignedDataOptions extends Partial<SignatureOptions> {
  plaintext: ArrayBuffer;
  signerCertificateSchema: CertificateSchema;
  signingKey: CryptoKey;
  serviceOid: string;
  expiryDate: Date;
  attributedMemberName?: Utf8String;
  shouldIncludeSignerCertificate: boolean;
}

async function generateSignedData(options: SignedDataOptions) {
  const {
    plaintext,
    signerCertificateSchema,
    signingKey,
    serviceOid,
    shouldEncapsulatePlaintext = false,
    expiryDate,
    startDate,
    attributedMemberName,
    shouldIncludeSignerCertificate,
  } = options;

  const signerCertificate = Certificate.deserialize(
    AsnSerializer.serialize(signerCertificateSchema),
  );
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

  const signedData = await SignedData.sign(
    plaintext,
    signingKey,
    signerCertificate,
    shouldIncludeSignerCertificate ? [signerCertificate] : [],
    {
      extraSignedAttrs,
      shouldEncapsulatePlaintext,
    },
  );
  return AsnParser.parse(signedData.serialize(), ContentInfo);
}

function getMetadata(signedData: SignedData) {
  const metadataAttributeAsn1 = signedData.getSignedAttribute(VERAID_OIDS.SIGNATURE_METADATA_ATTR);
  if (!metadataAttributeAsn1) {
    throw new VeraidError('Signature metadata is missing');
  }
  let metadata: SignatureMetadataSchema;
  try {
    metadata = AsnParser.parse(
      (metadataAttributeAsn1 as BaseBlock[])[0].toBER(),
      SignatureMetadataSchema,
    );
  } catch {
    throw new VeraidError('Signature metadata is malformed');
  }
  if (metadata.validityPeriod.end < metadata.validityPeriod.start) {
    throw new VeraidError('Signature validity period ends before it starts');
  }

  return metadata;
}

function convertDatePeriod(dateOrPeriod: Date | IDatePeriod) {
  if (dateOrPeriod instanceof Date) {
    return DatePeriod.init(dateOrPeriod, dateOrPeriod);
  }
  if (dateOrPeriod.end < dateOrPeriod.start) {
    throw new VeraidError('Verification expiry date cannot be before start date');
  }
  return DatePeriod.init(dateOrPeriod.start, dateOrPeriod.end);
}

function getSignaturePeriodIntersection(
  metadata: SignatureMetadataSchema,
  dateOrPeriod: Date | IDatePeriod,
) {
  const signaturePeriod = DatePeriod.init(
    metadata.validityPeriod.start,
    metadata.validityPeriod.end,
  );
  const verificationPeriod = convertDatePeriod(dateOrPeriod);
  const signaturePeriodIntersection = verificationPeriod.intersect(signaturePeriod);
  if (!signaturePeriodIntersection) {
    throw new VeraidError(
      `Signature period (${signaturePeriod.toString()}) ` +
        `does not overlap with required period (${verificationPeriod.toString()})`,
    );
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
  public static deserialise(serialisation: ArrayBuffer): SignatureBundle {
    const bundleSchema = AsnParser.parse(serialisation, SignatureBundleSchema);

    if (bundleSchema.version !== 0) {
      throw new VeraidError('Unsupported SignatureBundle version');
    }

    return new SignatureBundle(
      bundleSchema.dnssecChain,
      bundleSchema.organisationCertificate,
      bundleSchema.signature,
    );
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
  public static async sign(
    plaintext: ArrayBuffer,
    serviceOid: string,
    signer: MemberIdBundle | OrganisationSigner,
    signingKey: CryptoKey,
    expiryDate: Date,
    options: Partial<SignatureOptions> = {},
  ): Promise<SignatureBundle> {
    let signerCertificateSchema: CertificateSchema;
    let attributedMemberName: Utf8String | undefined;
    let shouldIncludeSignerCertificate: boolean;
    if (signer instanceof MemberIdBundleClass) {
      // It's a member signature bundle
      signerCertificateSchema = signer.memberCertificateSchema;
      attributedMemberName = undefined;
      shouldIncludeSignerCertificate = true;
    } else {
      // It's an organisation signature bundle
      signerCertificateSchema = signer.orgCertificateSchema;
      attributedMemberName = new Utf8String({
        value: signer.attributedMemberName ?? BOT_NAME,
      });
      shouldIncludeSignerCertificate = false;
    }

    const signedData = await generateSignedData({
      plaintext,
      signerCertificateSchema,
      signingKey,
      serviceOid,
      expiryDate,
      attributedMemberName,
      shouldIncludeSignerCertificate,
      ...options,
    });

    return new SignatureBundle(signer.dnssecChainSchema, signer.orgCertificateSchema, signedData);
  }

  public constructor(
    public readonly dnssecChainSchema: DnssecChainSchema,
    public readonly orgCertificateSchema: CertificateSchema,
    public readonly signature: ContentInfo,
  ) {}

  /**
   * Serialise this signature bundle to its binary representation
   * @returns The serialised signature bundle
   */
  public serialise(): ArrayBuffer {
    const signatureSchema = new SignatureBundleSchema();
    signatureSchema.version = 0;
    signatureSchema.dnssecChain = this.dnssecChainSchema;
    signatureSchema.organisationCertificate = this.orgCertificateSchema;
    signatureSchema.signature = this.signature;
    return AsnSerializer.serialize(signatureSchema);
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
  public async verify(
    plaintext: ArrayBuffer | undefined,
    serviceOid: string,
    dateOrPeriod: Date | IDatePeriod = new Date(),
    trustAnchors?: readonly TrustAnchor[],
  ): Promise<SignatureBundleVerification> {
    const signedData = SignedData.deserialize(AsnSerializer.serialize(this.signature));
    try {
      await signedData.verify(plaintext);
    } catch (err) {
      throw new VeraidError('Signature is invalid', { cause: err });
    }

    const metadata = getMetadata(signedData);
    if (metadata.serviceOid !== serviceOid) {
      throw new VeraidError(`Signature is bound to a different service (${metadata.serviceOid})`);
    }

    const signaturePeriodIntersection = getSignaturePeriodIntersection(metadata, dateOrPeriod);
    const memberIdBundle = new MemberIdBundleClass(
      this.dnssecChainSchema,
      this.orgCertificateSchema,
      AsnParser.parse(signedData.signerCertificate!.serialize(), CertificateSchema),
    );
    let member;
    try {
      member = await memberIdBundle.verify(serviceOid, signaturePeriodIntersection, trustAnchors);
    } catch (err) {
      throw new VeraidError('Member id bundle is invalid', { cause: err });
    }

    return { plaintext: plaintext ?? signedData.plaintext!, member, wasSignedByMember: true };
  }
}
