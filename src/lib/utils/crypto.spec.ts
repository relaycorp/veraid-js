import { jest } from '@jest/globals';

import { generateRandom64BitValue } from './crypto.js';
import { CRYPTO_ENGINE } from './pkijs.js';

const mockGetRandomValues = jest.spyOn(CRYPTO_ENGINE, 'getRandomValues');

test('generateRandom64BitValue() should generate a cryptographically secure value', () => {
  const expectedBytes: readonly number[] = [1, 2, 3, 4, 5, 6, 7, 8];
  mockGetRandomValues.mockImplementation((arrayView: ArrayBufferView | null) => {
    const buffer = new Uint8Array(arrayView!.buffer);
    buffer.set(expectedBytes);
    return arrayView;
  });

  const randomValue = generateRandom64BitValue();

  expect(mockGetRandomValues).toHaveBeenCalledWith(
    expect.toSatisfy<ArrayBuffer>((buffer) => buffer.byteLength === 8),
  );
  expect(Buffer.from(randomValue)).toStrictEqual(Buffer.from(expectedBytes));
});
