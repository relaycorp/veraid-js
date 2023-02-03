/* eslint-disable new-cap */

import { AsnProp, AsnPropTypes } from '@peculiar/asn1-schema';
import { SignedData } from '@peculiar/asn1-cms';
import { Certificate } from '@peculiar/asn1-x509';

import { DnssecChainSchema } from '../dns/DnssecChainSchema.js';

import { DatePeriodSchema } from './DatePeriodSchema.js';

export class VeraSignatureSchema {
  @AsnProp({ type: DatePeriodSchema })
  public validityPeriod!: DatePeriodSchema;

  @AsnProp({ type: AsnPropTypes.VisibleString })
  public serviceOid!: AsnPropTypes.VisibleString;

  @AsnProp({ type: DnssecChainSchema })
  public dnssecChain!: DnssecChainSchema;

  @AsnProp({ type: Certificate })
  public organisationCertificate!: Certificate;

  @AsnProp({ type: SignedData })
  public signature!: SignedData;
}
