/* eslint-disable new-cap */
import { AsnProp, AsnPropTypes } from '@peculiar/asn1-schema';

export class DatePeriodSchema {
  @AsnProp({ type: AsnPropTypes.GeneralizedTime, context: 0, implicit: true })
  public start!: Date;

  @AsnProp({ type: AsnPropTypes.GeneralizedTime, context: 1, implicit: true })
  public end!: Date;
}
