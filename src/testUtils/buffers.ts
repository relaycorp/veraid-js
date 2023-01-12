import { bufferToArray } from '../lib/utils/buffers.js';

export function arrayBufferFrom(input: Uint8Array | string): ArrayBuffer {
  return bufferToArray(Buffer.from(input));
}
