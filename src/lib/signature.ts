import { AsnParser, AsnSerializer } from '@peculiar/asn1-schema';
import { ContentInfo } from '@peculiar/asn1-cms';
import { type Certificate as CertificateSchema } from '@peculiar/asn1-x509';
import { type Sequence } from 'asn1js';
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

async function generateSignedData(
  plaintext: ArrayBuffer,
  memberCertificateSchema: CertificateSchema,
  signingKey: CryptoKey,
  serviceOid: string,
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
    encapsulatePlaintext: false,
  });
  return AsnParser.parse(signedData.serialize(), ContentInfo);
}

export async function sign(
  plaintext: ArrayBuffer,
  serviceOid: string,
  memberIdBundleSerialised: ArrayBuffer,
  signingKey: CryptoKey,
  expiryDate: Date,
  startDate?: Date,
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
    expiryDate,
    startDate,
  );

  const signatureSchema = new SignatureBundleSchema();
  signatureSchema.dnssecChain = memberIdBundleSchema.dnssecChain;
  signatureSchema.organisationCertificate = memberIdBundleSchema.organisationCertificate;
  signatureSchema.signature = signedDataSchema;
  return AsnSerializer.serialize(signatureSchema);
}
