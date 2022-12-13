import { type IBerConvertible } from 'asn1js';

export function asn1Serialise(asn1Value: IBerConvertible): Buffer {
  return Buffer.from(asn1Value.toBER());
}
