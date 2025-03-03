import type { Certificate as CertificateSchema } from '@peculiar/asn1-x509';
import { AsnSerializer } from '@peculiar/asn1-schema';
import type { TrustAnchor } from '@relaycorp/dnssec';

import type { DnssecChainSchema } from './schemas/DnssecChainSchema.js';
import type { DatePeriod } from './dates.js';
import Certificate from './utils/x509/Certificate.js';
import VeraidError from './VeraidError.js';
import { VeraidDnssecChain } from './dns/VeraidDnssecChain.js';
import { getKeySpec } from './dns/organisationKeys.js';
import type { Member } from './Member.js';
import { validateUserName } from './idValidation.js';

/**
 * Verify the certificate chain and return the intersection of the validity periods.
 */
async function verifyCertificateChain(
  orgCertificate: Certificate,
  signerCertificate: Certificate,
  datePeriod: DatePeriod,
): Promise<DatePeriod> {
  let certChain: readonly Certificate[];
  try {
    certChain = await signerCertificate.getCertificationPath([], [orgCertificate]);
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

export abstract class Chain {
  protected constructor(
    public readonly dnssecChainSchema: DnssecChainSchema,
    public readonly orgCertificateSchema: CertificateSchema,
  ) {}

  /**
   * Get the certificate schema of the signer.
   */
  public abstract get signerCertificateSchema(): CertificateSchema | undefined;

  /**
   * Get the name of the signer, if available.
   */
  public abstract get signerName(): string | undefined;

  /**
   * Verify the chain and return the member information.
   * @param serviceOid - The service OID to verify
   * @param datePeriod - The date period to verify
   * @param dnssecTrustAnchors - The DNSSEC trust anchors to use for verification
   * @returns The member information
   */
  public async verify(
    serviceOid: string,
    datePeriod: DatePeriod,
    dnssecTrustAnchors?: readonly TrustAnchor[],
  ): Promise<Member> {
    const orgCertificate = Certificate.deserialize(
      AsnSerializer.serialize(this.orgCertificateSchema),
    );

    const signerCertificate =
      this.signerCertificateSchema === undefined
        ? orgCertificate
        : Certificate.deserialize(AsnSerializer.serialize(this.signerCertificateSchema));

    const certChainPeriod = await verifyCertificateChain(
      orgCertificate,
      signerCertificate,
      datePeriod,
    );

    const dnssecChain = new VeraidDnssecChain(orgCertificate.commonName, this.dnssecChainSchema);
    const keySpec = await getKeySpec(await orgCertificate.getPublicKey());
    await dnssecChain.verify(keySpec, serviceOid, certChainPeriod, dnssecTrustAnchors);

    const organisation = orgCertificate.commonName.replace(/\.$/u, '');
    const user = this.signerName;
    if (user !== undefined) {
      validateUserName(user);
    }
    return { organisation, user };
  }
}
