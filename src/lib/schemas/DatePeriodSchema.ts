/* eslint-disable new-cap */
import { AsnProp, AsnPropTypes } from '@peculiar/asn1-schema';

export class DatePeriodSchema {
  @AsnProp({ type: AsnPropTypes.GeneralizedTime })
  public start!: Date;

  @AsnProp({ type: AsnPropTypes.GeneralizedTime })
  public end!: Date;
}
