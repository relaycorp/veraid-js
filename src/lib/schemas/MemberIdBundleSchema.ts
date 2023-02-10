/* eslint-disable new-cap */

import { AsnProp, AsnPropTypes } from '@peculiar/asn1-schema';
import { Certificate } from '@peculiar/asn1-x509';

import { DnssecChainSchema } from './DnssecChainSchema.js';

export class MemberIdBundleSchema {
  @AsnProp({ type: AsnPropTypes.Integer })
  public version!: number;

  @AsnProp({ type: DnssecChainSchema })
  public dnssecChain!: DnssecChainSchema;

  @AsnProp({ type: Certificate })
  public organisationCertificate!: Certificate;

  @AsnProp({ type: Certificate })
  public memberCertificate!: Certificate;
}
