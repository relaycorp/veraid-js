import { ContentInfo } from '@peculiar/asn1-cms';
import type { Certificate as CertificateSchema } from '@peculiar/asn1-x509';
import { AsnParser, AsnSerializer } from '@peculiar/asn1-schema';
import { Attribute } from 'pkijs';
import type { Sequence } from 'asn1js';

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
import type { MemberIdBundle } from './memberIdBundle/MemberIdBundle.js';

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
    type: VERAID_OIDS.SIGNATURE_METADATA_ATTR,
    values: [metadataSchema],
  });
  const signedData = await SignedData.sign(plaintext, signingKey, memberCertificate, [], {
    extraSignedAttrs: [metadataAttribute],
    encapsulatePlaintext: shouldEncapsulatePlaintext,
  });
  return AsnParser.parse(signedData.serialize(), ContentInfo);
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
   * Create a signature for the specified plaintext using the provided member ID
   * @param plaintext - The data to sign
   * @param serviceOid - The OID of the service for which the signature is created
   * @param signer - The member ID bundle to use for signing
   * @param signingKey - The private key corresponding to the member certificate
   * @param expiryDate - The date when the signature expires
   * @param options - Additional options for signature creation
   * @param options.startDate - The date when the signature becomes valid (defaults to now)
   * @param options.shouldEncapsulatePlaintext - Whether to include the plaintext in the signature (defaults to false)
   * @returns A new SignatureBundle instance
   */
  public static async sign(
    plaintext: ArrayBuffer,
    serviceOid: string,
    signer: MemberIdBundle,
    signingKey: CryptoKey,
    expiryDate: Date,
    { startDate, shouldEncapsulatePlaintext }: Partial<SignatureOptions> = {},
  ): Promise<SignatureBundle> {
    const signedDataSchema = await generateSignedData(
      plaintext,
      signer.memberCertificateSchema,
      signingKey,
      serviceOid,
      shouldEncapsulatePlaintext ?? false,
      expiryDate,
      startDate,
    );

    return new SignatureBundle(
      signer.dnssecChainSchema,
      signer.orgCertificateSchema,
      signedDataSchema,
    );
  }

  public constructor(
    protected readonly dnssecChainSchema: DnssecChainSchema,
    protected readonly orgCertificateSchema: CertificateSchema,
    protected readonly signature: ContentInfo,
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
}
