import { Integer } from 'asn1js';
import bufferToArray from 'buffer-to-arraybuffer';

import { derDeserialize } from './asn1.js';

describe('deserializeDer', () => {
  test('should return ASN.1 object given a valid DER-encoded buffer', () => {
    const asn1Value = new Integer({ value: 3 });
    const derValue = asn1Value.toBER(false);

    const deserializedValue = derDeserialize(derValue);
    expect(deserializedValue).toHaveProperty('idBlock.tagClass', asn1Value.idBlock.tagClass);
    expect(deserializedValue).toHaveProperty('idBlock.tagNumber', asn1Value.idBlock.tagNumber);
    expect(deserializedValue).toHaveProperty('valueBlock.valueDec', asn1Value.valueBlock.valueDec);
  });

  test('should fail when passed a non-DER encoded value', () => {
    const invalidDerValue = bufferToArray(Buffer.from('hi'));
    expect(() => derDeserialize(invalidDerValue)).toThrow(new Error('Value is not DER-encoded'));
  });
});
