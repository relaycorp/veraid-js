import { type IBerConvertible } from 'asn1js';

export function asn1Serialise(asn1Value: IBerConvertible): Buffer {
  return Buffer.from(asn1Value.toBER());
}

export function expectAsn1ValuesToBeEqual(
  expectedValue: IBerConvertible,
  actualValue: IBerConvertible,
): void {
  expect(Buffer.from(actualValue.toBER(false))).toEqual(Buffer.from(expectedValue.toBER(false)));
}
