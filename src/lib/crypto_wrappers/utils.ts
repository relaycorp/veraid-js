import { type AsnType, fromBER } from 'asn1js';
import { getCrypto } from 'pkijs';

export function getPkijsCrypto(): SubtleCrypto {
  const cryptoEngine = getCrypto();
  if (!cryptoEngine) {
    throw new Error('PKI.js crypto engine is undefined');
  }
  return cryptoEngine;
}

export function derDeserialize(derValue: ArrayBuffer): AsnType {
  const asn1Value = fromBER(derValue);
  // eslint-disable-next-line @typescript-eslint/no-magic-numbers
  if (asn1Value.offset === -1) {
    throw new Error('Value is not DER-encoded');
  }
  return asn1Value.result;
}

export function generateRandom64BitValue(): ArrayBuffer {
  // eslint-disable-next-line @typescript-eslint/no-magic-numbers
  const value = new ArrayBuffer(8);
  getPkijsCrypto().getRandomValues(new Uint8Array(value));
  return value;
}
