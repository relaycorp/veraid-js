import type { TrustAnchor } from '@relaycorp/dnssec';
import type { Certificate as CertificateSchema } from '@peculiar/asn1-x509';
import { AsnParser, AsnSerializer } from '@peculiar/asn1-schema';
import { ContentInfo } from '@peculiar/asn1-cms';
import { Attribute } from 'pkijs';
import type { Sequence } from 'asn1js';

import type { DnssecChainSchema } from '../schemas/DnssecChainSchema.js';
import type { DatePeriod } from '../dates.js';
import Certificate from '../utils/x509/Certificate.js';
import VeraidError from '../VeraidError.js';
import { VeraidDnssecChain } from '../dns/VeraidDnssecChain.js';
import { getKeySpec } from '../dns/organisationKeys.js';
import { MemberIdBundleSchema } from '../schemas/MemberIdBundleSchema.js';
import type { Member } from '../Member.js';
import { BOT_NAME } from '../pki/member.js';
import { validateUserName } from '../idValidation.js';
import { SignatureBundleSchema } from '../schemas/SignatureBundleSchema.js';
import { VERAID_OIDS } from '../oids.js';
import { SignatureMetadataSchema } from '../schemas/SignatureMetadataSchema.js';
import { DatePeriodSchema } from '../schemas/DatePeriodSchema.js';
import { derDeserialize } from '../utils/asn1.js';
import { SignedData } from '../utils/cms/SignedData.js';
import type { SignatureOptions } from '../SignatureOptions.js';

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

async function verifyCertificateChain(
  orgCertificate: Certificate,
  memberCertificate: Certificate,
  datePeriod: DatePeriod,
): Promise<DatePeriod> {
  let certChain: readonly Certificate[];
  try {
    certChain = await memberCertificate.getCertificationPath([], [orgCertificate]);
  } catch (err) {
    throw new VeraidError('Member certificate was not issued by organisation', { cause: err });
  }
  const certChainPeriod = certChain
    .map((certificate) => certificate.validityPeriod)
    .reduce((previousValue, currentValue) => previousValue.intersect(currentValue)!);

  const intersection = certChainPeriod.intersect(datePeriod);
  if (!intersection) {
    throw new VeraidError(
      `Validity period of certificate chain (${certChainPeriod.toString()}) ` +
        `does not overlap with required period (${datePeriod.toString()})`,
    );
  }
  return intersection;
}

/**
 * VeraId member identity bundle containing certificates and DNSSEC chain
 */
export class MemberIdBundle {
  /**
   * Deserialise a member ID bundle from its binary representation
   * @param memberIdBundleSerialised - The serialised member ID bundle
   * @returns A new MemberIdBundle instance
   * @throws If the bundle is malformed
   */
  public static deserialise(memberIdBundleSerialised: ArrayBuffer): MemberIdBundle {
    let memberIdBundleSchema: MemberIdBundleSchema;
    try {
      memberIdBundleSchema = AsnParser.parse(memberIdBundleSerialised, MemberIdBundleSchema);
    } catch {
      throw new VeraidError('Member id bundle is malformed');
    }

    return new MemberIdBundle(
      memberIdBundleSchema.dnssecChain,
      memberIdBundleSchema.organisationCertificate,
      memberIdBundleSchema.memberCertificate,
    );
  }

  public constructor(
    protected readonly dnssecChainSchema: DnssecChainSchema,
    protected readonly orgCertificateSchema: CertificateSchema,
    protected readonly memberCertificateSchema: CertificateSchema,
  ) {}

  /**
   * Serialise this member ID bundle to its binary representation
   * @returns The serialised member ID bundle
   */
  public serialise(): ArrayBuffer {
    const bundle = new MemberIdBundleSchema();
    bundle.version = 0;
    bundle.memberCertificate = this.memberCertificateSchema;
    bundle.organisationCertificate = this.orgCertificateSchema;
    bundle.dnssecChain = this.dnssecChainSchema;
    return AsnSerializer.serialize(bundle);
  }

  /**
   * Create a signature for the specified plaintext using this member ID
   * @param plaintext - The data to sign
   * @param serviceOid - The OID of the service for which the signature is created
   * @param signingKey - The private key corresponding to the member certificate
   * @param expiryDate - The date when the signature expires
   * @param options - Additional options for signature creation
   * @param options.startDate - The date when the signature becomes valid (defaults to now)
   * @param options.shouldEncapsulatePlaintext - Whether to include the plaintext in the signature (defaults to false)
   * @returns A serialised SignatureBundle
   */
  public async sign(
    plaintext: ArrayBuffer,
    serviceOid: string,
    signingKey: CryptoKey,
    expiryDate: Date,
    { startDate, shouldEncapsulatePlaintext }: Partial<SignatureOptions> = {},
  ): Promise<ArrayBuffer> {
    const signedDataSchema = await generateSignedData(
      plaintext,
      this.memberCertificateSchema,
      signingKey,
      serviceOid,
      shouldEncapsulatePlaintext ?? false,
      expiryDate,
      startDate,
    );

    const signatureSchema = new SignatureBundleSchema();
    signatureSchema.version = 0;
    signatureSchema.dnssecChain = this.dnssecChainSchema;
    signatureSchema.organisationCertificate = this.orgCertificateSchema;
    signatureSchema.signature = signedDataSchema;
    return AsnSerializer.serialize(signatureSchema);
  }

  /**
   * Verify this member ID bundle against the specified service and time period
   * @param serviceOid - The OID of the service for which the bundle should be valid
   * @param datePeriod - The time period during which the bundle should be valid
   * @param dnssecTrustAnchors - The DNSSEC trust anchors to use for verification
   * @returns The verified member information
   * @throws If verification fails
   */
  public async verify(
    serviceOid: string,
    datePeriod: DatePeriod,
    dnssecTrustAnchors?: readonly TrustAnchor[],
  ): Promise<Member> {
    const orgCertificate = Certificate.deserialize(
      AsnSerializer.serialize(this.orgCertificateSchema),
    );
    const memberCertificate = Certificate.deserialize(
      AsnSerializer.serialize(this.memberCertificateSchema),
    );
    const certChainPeriod = await verifyCertificateChain(
      orgCertificate,
      memberCertificate,
      datePeriod,
    );

    const dnssecChain = new VeraidDnssecChain(orgCertificate.commonName, this.dnssecChainSchema);
    const keySpec = await getKeySpec(await orgCertificate.getPublicKey());
    await dnssecChain.verify(keySpec, serviceOid, certChainPeriod, dnssecTrustAnchors);

    const organisation = orgCertificate.commonName.replace(/\.$/u, '');
    const user =
      memberCertificate.commonName === BOT_NAME ? undefined : memberCertificate.commonName;
    if (user !== undefined) {
      validateUserName(user);
    }
    return { organisation, user };
  }
}
