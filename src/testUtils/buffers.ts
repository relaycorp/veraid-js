import { bufferToArray } from '../lib/utils/buffers.js';

export function arrayBufferFrom(input: Buffer | string): ArrayBuffer {
  return bufferToArray(Buffer.from(input));
}
