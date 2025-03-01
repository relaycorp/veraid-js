import type { TrustAnchor } from '@relaycorp/dnssec';
import type { Certificate as CertificateSchema } from '@peculiar/asn1-x509';
import { AsnParser, AsnSerializer } from '@peculiar/asn1-schema';

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
    public readonly dnssecChainSchema: DnssecChainSchema,
    public readonly orgCertificateSchema: CertificateSchema,
    public readonly memberCertificateSchema: CertificateSchema,
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
