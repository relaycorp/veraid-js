import { type Certificate as CertificateSchema } from '@peculiar/asn1-x509';
import { AsnSerializer } from '@peculiar/asn1-schema';

import { type DnssecChainSchema } from '../dns/DnssecChainSchema.js';

import { MemberIdBundleSchema } from './MemberIdBundleSchema.js';

export class MemberIdBundle {
  public constructor(
    protected readonly veraChain: DnssecChainSchema,
    protected readonly organisationCertificate: CertificateSchema,
    protected readonly memberCertificate: CertificateSchema,
  ) {}

  public serialise(): ArrayBuffer {
    const bundle = new MemberIdBundleSchema();
    bundle.memberCertificate = this.memberCertificate;
    bundle.organisationCertificate = this.organisationCertificate;
    bundle.dnssecChain = this.veraChain;
    return AsnSerializer.serialize(bundle);
  }
}
