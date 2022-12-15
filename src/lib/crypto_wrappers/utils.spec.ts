import { beforeEach, jest } from '@jest/globals';
import { Crypto } from '@peculiar/webcrypto';
import { Integer } from 'asn1js';
import bufferToArray from 'buffer-to-arraybuffer';
import { CryptoEngine, getEngine, type ICryptoEngine, setEngine } from 'pkijs';

import { derDeserialize, generateRandom64BitValue, getPkijsCrypto } from './utils.js';

const originalEngine = getEngine();
beforeEach(() => {
  setEngine(originalEngine.name, originalEngine.crypto!);
});

describe('getPkijsCrypto', () => {
  test('It should pass on the crypto object it got', () => {
    const stubEngine = new CryptoEngine({ crypto: new Crypto() });
    setEngine(stubEngine.name, stubEngine);

    const crypto = getPkijsCrypto();

    expect(crypto).toBe(stubEngine);
  });

  test('It should error out if there is no crypto object', () => {
    setEngine(originalEngine.name, undefined);

    expect(getPkijsCrypto).toThrow('PKI.js crypto engine is undefined');
  });
});

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

test('generateRandom64BitValue() should generate a cryptographically secure value', () => {
  const expectedBytes: readonly number[] = [1, 2, 3, 4, 5, 6, 7, 8];
  const mockWebcrypto = {
    getRandomValues: jest
      .fn<(array: Uint8Array) => void>()
      .mockImplementation((array: Uint8Array) => {
        array.set(expectedBytes);
      }),
  };
  setEngine(originalEngine.name, mockWebcrypto as unknown as ICryptoEngine);

  const randomValue = generateRandom64BitValue();

  expect(randomValue).toBeInstanceOf(ArrayBuffer);
  expect(randomValue).toHaveProperty('byteLength', 8);

  expect(Buffer.from(randomValue)).toStrictEqual(Buffer.from(expectedBytes));
});
