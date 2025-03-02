import type { Certificate as CertificateSchema } from '@peculiar/asn1-x509';

import type { DnssecChainSchema } from './schemas/DnssecChainSchema.js';

export abstract class Chain {
  protected constructor(
    public readonly dnssecChainSchema: DnssecChainSchema,
    public readonly orgCertificateSchema: CertificateSchema,
  ) {}
}
