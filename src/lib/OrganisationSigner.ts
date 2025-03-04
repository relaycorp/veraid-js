import type { Certificate as CertificateSchema } from '@peculiar/asn1-x509';

import { Chain } from './Chain.js';
import type { DnssecChainSchema } from './schemas/DnssecChainSchema.js';

/**
 * Configuration for organisation signature bundles.
 */
export class OrganisationSigner extends Chain {
  /**
   * @param dnssecChainSchema - The DNSSEC chain for the organisation
   * @param orgCertificateSchema - The organisation certificate
   * @param attributedMemberName - The name of the member to whom the content is attributed (optional)
   */
  public constructor(
    dnssecChainSchema: DnssecChainSchema,
    orgCertificateSchema: CertificateSchema,
    public readonly attributedMemberName?: string,
  ) {
    super(dnssecChainSchema, orgCertificateSchema);
  }

  public override get signerCertificateSchema() {
    return undefined;
  }

  public override get signerName() {
    return this.attributedMemberName;
  }
}
