import type { Message } from '@relaycorp/dnssec';

export function serialiseMessage(message: Message): Buffer {
  return Buffer.from(message.serialise());
}
