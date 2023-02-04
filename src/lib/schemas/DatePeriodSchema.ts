/* eslint-disable new-cap */
import { AsnProp, AsnPropTypes } from '@peculiar/asn1-schema';

export class DatePeriodSchema {
  @AsnProp({ type: AsnPropTypes.UTCTime })
  public start!: Date;

  @AsnProp({ type: AsnPropTypes.UTCTime })
  public end!: Date;
}
