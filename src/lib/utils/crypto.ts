import { getPkijsCrypto } from './pkijs.js';

const SIXTY_FOUR_BITS_IN_OCTETS = 8;

export function generateRandom64BitValue(): ArrayBuffer {
  const value = new ArrayBuffer(SIXTY_FOUR_BITS_IN_OCTETS);
  getPkijsCrypto().getRandomValues(new Uint8Array(value));
  return value;
}
