import { Chain } from './Chain.js';
import type { VeraidDnssecChain } from './dns/VeraidDnssecChain.js';
import type Certificate from './utils/x509/Certificate.js';

/**
 * Configuration for organisation signature bundles.
 */
export class OrganisationSigner extends Chain {
  /**
   * @param dnssecChain - The DNSSEC chain for the organisation
   * @param orgCertificate - The organisation certificate
   * @param attributedMemberName - The name of the member to whom the content is attributed (optional)
   */
  public constructor(
    dnssecChain: VeraidDnssecChain,
    orgCertificate: Certificate,
    public readonly attributedMemberName?: string,
  ) {
    super(dnssecChain, orgCertificate);
  }

  public override get signerCertificate() {
    return undefined;
  }

  public override get signerName() {
    return this.attributedMemberName;
  }
}
