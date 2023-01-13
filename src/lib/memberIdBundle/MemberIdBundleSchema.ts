/* eslint-disable new-cap */
import { AsnProp } from '@peculiar/asn1-schema';
import { Certificate } from '@peculiar/asn1-x509';

import { DnssecChain } from '../dns/DnssecChain.js';

export class MemberIdBundleSchema {
  @AsnProp({ type: DnssecChain })
  public dnssecChain!: DnssecChain;

  @AsnProp({ type: Certificate })
  public organisationCertificate!: Certificate;

  @AsnProp({ type: Certificate })
  public memberCertificate!: Certificate;
}
