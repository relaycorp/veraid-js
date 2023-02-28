/* eslint-disable new-cap */

import { AsnProp, AsnPropTypes } from '@peculiar/asn1-schema';

import { DatePeriodSchema } from './DatePeriodSchema.js';

export class SignatureMetadataSchema {
  @AsnProp({ type: AsnPropTypes.ObjectIdentifier })
  public serviceOid!: string;

  @AsnProp({ type: DatePeriodSchema })
  public validityPeriod!: DatePeriodSchema;
}
