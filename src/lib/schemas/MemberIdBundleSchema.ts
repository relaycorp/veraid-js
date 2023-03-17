/* eslint-disable new-cap */

import { AsnProp, AsnPropTypes } from '@peculiar/asn1-schema';
import { Certificate } from '@peculiar/asn1-x509';

import { DnssecChainSchema } from './DnssecChainSchema.js';

export class MemberIdBundleSchema {
  @AsnProp({ type: AsnPropTypes.Integer, context: 0, implicit: true })
  public version!: number;

  @AsnProp({ type: DnssecChainSchema, context: 1, implicit: true })
  public dnssecChain!: DnssecChainSchema;

  @AsnProp({ type: Certificate, context: 2, implicit: true })
  public organisationCertificate!: Certificate;

  @AsnProp({ type: Certificate, context: 3, implicit: true })
  public memberCertificate!: Certificate;
}
