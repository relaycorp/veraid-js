/* eslint-disable new-cap */

import { AsnProp, AsnPropTypes } from '@peculiar/asn1-schema';

import { DatePeriodSchema } from './DatePeriodSchema.js';

export class VeraSignatureMetadataSchema {
  @AsnProp({ type: AsnPropTypes.VisibleString })
  public serviceOid!: AsnPropTypes.VisibleString;

  @AsnProp({ type: DatePeriodSchema })
  public validityPeriod!: DatePeriodSchema;
}
