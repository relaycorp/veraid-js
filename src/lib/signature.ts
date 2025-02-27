import type { TrustAnchor } from '@relaycorp/dnssec';
import { AsnParser, AsnSerializer } from '@peculiar/asn1-schema';
import { Certificate as CertificateSchema } from '@peculiar/asn1-x509';
import type { BaseBlock } from 'asn1js';

import VeraidError from './VeraidError.js';
import { SignedData } from './utils/cms/SignedData.js';
import { SignatureBundleSchema } from './schemas/SignatureBundleSchema.js';
import { VERAID_OIDS } from './oids.js';
import { SignatureMetadataSchema } from './schemas/SignatureMetadataSchema.js';
import { DatePeriod, type IDatePeriod } from './dates.js';
import { MemberIdBundle } from './memberIdBundle/MemberIdBundle.js';
import type { SignatureBundleVerification } from './SignatureBundleVerification.js';

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
    throw new VeraidError('Signature bundle is malformed');
  }

  const signedData = SignedData.deserialize(AsnSerializer.serialize(signatureBundle.signature));
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
  const memberIdBundle = new MemberIdBundle(
    signatureBundle.dnssecChain,
    signatureBundle.organisationCertificate,
    AsnParser.parse(signedData.signerCertificate!.serialize(), CertificateSchema),
  );
  let member;
  try {
    member = await memberIdBundle.verify(serviceOid, signaturePeriodIntersection, trustAnchors);
  } catch (err) {
    throw new VeraidError('Member id bundle is invalid', { cause: err });
  }
  return { plaintext: plaintext ?? signedData.plaintext!, member };
}
