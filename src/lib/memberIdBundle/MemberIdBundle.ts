import type { TrustAnchor } from '@relaycorp/dnssec';
import type { Certificate as CertificateSchema } from '@peculiar/asn1-x509';
import { AsnSerializer } from '@peculiar/asn1-schema';

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

export class MemberIdBundle {
  public constructor(
    protected readonly veraChainSchema: DnssecChainSchema,
    protected readonly orgCertificateSchema: CertificateSchema,
    protected readonly memberCertificateSchema: CertificateSchema,
  ) {}

  public serialise(): ArrayBuffer {
    const bundle = new MemberIdBundleSchema();
    bundle.version = 0;
    bundle.memberCertificate = this.memberCertificateSchema;
    bundle.organisationCertificate = this.orgCertificateSchema;
    bundle.dnssecChain = this.veraChainSchema;
    return AsnSerializer.serialize(bundle);
  }

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

    const dnssecChain = new VeraidDnssecChain(orgCertificate.commonName, this.veraChainSchema);
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
