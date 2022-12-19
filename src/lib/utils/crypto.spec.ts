import { jest } from '@jest/globals';
import { getEngine, type ICryptoEngine, setEngine } from 'pkijs';

import { generateRandom64BitValue } from './crypto.js';

const originalEngine = getEngine();
const restoreEngine = () => {
  setEngine(originalEngine.name, originalEngine.crypto!);
};
beforeEach(restoreEngine);
afterAll(restoreEngine);

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

  expect(mockWebcrypto.getRandomValues).toHaveBeenCalledWith(
    expect.toSatisfy<ArrayBuffer>((buffer) => buffer.byteLength === 8),
  );
  expect(Buffer.from(randomValue)).toStrictEqual(Buffer.from(expectedBytes));
});
