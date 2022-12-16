import { type AsnType, fromBER } from 'asn1js';

export function derDeserialize(derValue: ArrayBuffer): AsnType {
  const asn1Value = fromBER(derValue);
  // eslint-disable-next-line @typescript-eslint/no-magic-numbers
  if (asn1Value.offset === -1) {
    throw new Error('Value is not DER-encoded');
  }
  return asn1Value.result;
}
