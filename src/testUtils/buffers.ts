import bufferToArray from 'buffer-to-arraybuffer';

export function arrayBufferFrom(input: Buffer | string): ArrayBuffer {
  return bufferToArray(Buffer.from(input));
}
