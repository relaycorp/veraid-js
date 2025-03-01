import type { Certificate as CertificateSchema } from '@peculiar/asn1-x509';

import type { DnssecChainSchema } from './schemas/DnssecChainSchema.js';

/**
 * Configuration for organisation signature bundles.
 */
export interface OrganisationSigner {
  /**
   * The organisation certificate.
   */
  readonly orgCertificateSchema: CertificateSchema;

  /**
   * The DNSSEC chain for the organisation.
   */
  readonly dnssecChainSchema: DnssecChainSchema;

  /**
   * The name of the member to whom the content is attributed.
   *
   * If absent, the content is attributed to the organisation.
   */
  readonly attributedMemberName?: string;
}
