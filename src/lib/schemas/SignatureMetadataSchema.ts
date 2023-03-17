/* eslint-disable new-cap */

import { AsnProp, AsnPropTypes } from '@peculiar/asn1-schema';

import { DatePeriodSchema } from './DatePeriodSchema.js';

export class SignatureMetadataSchema {
  @AsnProp({ type: AsnPropTypes.ObjectIdentifier, context: 0, implicit: true })
  public serviceOid!: string;

  @AsnProp({ type: DatePeriodSchema, context: 1, implicit: true })
  public validityPeriod!: DatePeriodSchema;
}
