import { NODE_ENGINE } from './pkijs.js';
const SIXTY_FOUR_BITS_IN_OCTETS = 8;
export function generateRandom64BitValue() {
    const value = new ArrayBuffer(SIXTY_FOUR_BITS_IN_OCTETS);
    NODE_ENGINE.getRandomValues(new Uint8Array(value));
    return value;
}
//# sourceMappingURL=crypto.js.map