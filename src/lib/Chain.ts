import type { TrustAnchor } from '@relaycorp/dnssec';

import type { DatePeriod } from './dates.js';
import type Certificate from './utils/x509/Certificate.js';
import VeraidError from './VeraidError.js';
import type { VeraidDnssecChain } from './dns/VeraidDnssecChain.js';
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
    public readonly dnssecChain: VeraidDnssecChain,
    public readonly orgCertificate: Certificate,
  ) {}

  /**
   * Get the certificate of the signer.
   * @internal
   */
  public abstract get signerCertificate(): Certificate | undefined;

  /**
   * Get the name of the signer, if available.
   * @internal
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
    const signerCertificate = this.signerCertificate ?? this.orgCertificate;

    const certChainPeriod = await verifyCertificateChain(
      this.orgCertificate,
      signerCertificate,
      datePeriod,
    );

    const keySpec = await getKeySpec(await this.orgCertificate.getPublicKey());
    await this.dnssecChain.verify(keySpec, serviceOid, certChainPeriod, dnssecTrustAnchors);

    const organisation = this.orgCertificate.commonName.replace(/\.$/u, '');
    const user = this.signerName;
    if (user !== undefined) {
      validateUserName(user);
    }
    return { organisation, user };
  }
}
