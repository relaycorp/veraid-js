import type { TrustAnchor } from '@relaycorp/dnssec';
import { AsnParser, AsnSerializer } from '@peculiar/asn1-schema';
import { ContentInfo } from '@peculiar/asn1-cms';
import { Certificate as CertificateSchema } from '@peculiar/asn1-x509';
import type { BaseBlock, Sequence } from 'asn1js';
import { Attribute } from 'pkijs';

import { MemberIdBundleSchema } from './schemas/MemberIdBundleSchema.js';
import VeraError from './VeraError.js';
import { SignedData } from './utils/cms/SignedData.js';
import Certificate from './utils/x509/Certificate.js';
import { SignatureBundleSchema } from './schemas/SignatureBundleSchema.js';
import { VERA_OIDS } from './oids.js';
import { SignatureMetadataSchema } from './schemas/SignatureMetadataSchema.js';
import { DatePeriodSchema } from './schemas/DatePeriodSchema.js';
import { derDeserialize } from './utils/asn1.js';
import { DatePeriod, type IDatePeriod } from './dates.js';
import { MemberIdBundle } from './memberIdBundle/MemberIdBundle.js';
import type { SignatureBundleVerification } from './SignatureBundleVerification.js';

function generateMetadata(serviceOid: string, startDate: Date, expiryDate: Date): Sequence {
  if (expiryDate < startDate) {
    throw new VeraError('Signature start date cannot be after expiry date');
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

function getMetadata(signedData: SignedData) {
  const metadataAttributeAsn1 = signedData.getSignedAttribute(VERA_OIDS.SIGNATURE_METADATA_ATTR);
  if (!metadataAttributeAsn1) {
    throw new VeraError('Signature metadata is missing');
  }
  let metadata: SignatureMetadataSchema;
  try {
    metadata = AsnParser.parse(
      (metadataAttributeAsn1 as BaseBlock[])[0].toBER(),
      SignatureMetadataSchema,
    );
  } catch {
    throw new VeraError('Signature metadata is malformed');
  }
  if (metadata.validityPeriod.end < metadata.validityPeriod.start) {
    throw new VeraError('Signature validity period ends before it starts');
  }

  return metadata;
}

function convertDatePeriod(dateOrPeriod: Date | IDatePeriod) {
  if (dateOrPeriod instanceof Date) {
    return DatePeriod.init(dateOrPeriod, dateOrPeriod);
  }
  if (dateOrPeriod.end < dateOrPeriod.start) {
    throw new VeraError('Verification expiry date cannot be before start date');
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
    throw new VeraError('Signature period does not overlap with required period');
  }
  return signaturePeriodIntersection;
}

async function generateSignedData(
  plaintext: ArrayBuffer,
  memberCertificateSchema: CertificateSchema,
  signingKey: CryptoKey,
  serviceOid: string,
  shouldEncapsulatePlaintext: boolean,
  expiryDate: Date,
  startDate?: Date,
) {
  const memberCertificate = Certificate.deserialize(
    AsnSerializer.serialize(memberCertificateSchema),
  );
  const metadataSchema = generateMetadata(serviceOid, startDate ?? new Date(), expiryDate);
  const metadataAttribute = new Attribute({
    type: VERA_OIDS.SIGNATURE_METADATA_ATTR,
    values: [metadataSchema],
  });
  const signedData = await SignedData.sign(plaintext, signingKey, memberCertificate, [], {
    extraSignedAttrs: [metadataAttribute],
    encapsulatePlaintext: shouldEncapsulatePlaintext,
  });
  return AsnParser.parse(signedData.serialize(), ContentInfo);
}

export interface SignatureOptions {
  readonly startDate: Date;
  readonly shouldEncapsulatePlaintext: boolean;
}

export async function sign(
  plaintext: ArrayBuffer,
  serviceOid: string,
  memberIdBundleSerialised: ArrayBuffer,
  signingKey: CryptoKey,
  expiryDate: Date,
  { startDate, shouldEncapsulatePlaintext }: Partial<SignatureOptions> = {},
): Promise<ArrayBuffer> {
  let memberIdBundleSchema: MemberIdBundleSchema;
  try {
    memberIdBundleSchema = AsnParser.parse(memberIdBundleSerialised, MemberIdBundleSchema);
  } catch {
    throw new VeraError('Member id bundle is malformed');
  }

  const signedDataSchema = await generateSignedData(
    plaintext,
    memberIdBundleSchema.memberCertificate,
    signingKey,
    serviceOid,
    shouldEncapsulatePlaintext ?? false,
    expiryDate,
    startDate,
  );

  const signatureSchema = new SignatureBundleSchema();
  signatureSchema.version = 0;
  signatureSchema.dnssecChain = memberIdBundleSchema.dnssecChain;
  signatureSchema.organisationCertificate = memberIdBundleSchema.organisationCertificate;
  signatureSchema.signature = signedDataSchema;
  return AsnSerializer.serialize(signatureSchema);
}

export async function verify(
  plaintext: ArrayBuffer | undefined,
  signatureBundleSerialised: ArrayBuffer,
  serviceOid: string,
  dateOrPeriod: Date | IDatePeriod = new Date(),
  trustAnchors?: readonly TrustAnchor[],
): Promise<SignatureBundleVerification> {
  let signatureBundle: SignatureBundleSchema;
  try {
    signatureBundle = AsnParser.parse(signatureBundleSerialised, SignatureBundleSchema);
  } catch {
    throw new VeraError('Signature bundle is malformed');
  }

  const signedData = SignedData.deserialize(AsnSerializer.serialize(signatureBundle.signature));
  try {
    await signedData.verify(plaintext);
  } catch (err) {
    throw new VeraError('Signature is invalid', { cause: err });
  }

  const metadata = getMetadata(signedData);
  if (metadata.serviceOid !== serviceOid) {
    throw new VeraError(`Signature is bound to a different service (${metadata.serviceOid})`);
  }

  const signaturePeriodIntersection = getSignaturePeriodIntersection(metadata, dateOrPeriod);
  const memberIdBundle = new MemberIdBundle(
    signatureBundle.dnssecChain,
    signatureBundle.organisationCertificate,
    AsnParser.parse(signedData.signerCertificate!.serialize(), CertificateSchema),
  );
  let member;
  try {
    member = await memberIdBundle.verify(serviceOid, signaturePeriodIntersection, trustAnchors);
  } catch (err) {
    throw new VeraError('Member id bundle is invalid', { cause: err });
  }
  return { plaintext: plaintext ?? signedData.plaintext!, member };
}
