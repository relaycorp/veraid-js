import { getPkijsCrypto } from './pkijs.js';

export function generateRandom64BitValue(): ArrayBuffer {
  // eslint-disable-next-line @typescript-eslint/no-magic-numbers
  const value = new ArrayBuffer(8);
  getPkijsCrypto().getRandomValues(new Uint8Array(value));
  return value;
}
