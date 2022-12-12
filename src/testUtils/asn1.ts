import { BaseBlock } from 'asn1js';
import { ContentInfo } from 'pkijs';

import { derDeserialize } from '../lib/crypto_wrappers/utils.js';

export function serializeContentInfo(content: BaseBlock<any>, contentType: string): ArrayBuffer {
  const contentInfo = new ContentInfo({ content, contentType });
  return contentInfo.toSchema().toBER(false);
}

// TODO: DELETE
export function deserializeContentInfo(contentInfoDer: ArrayBuffer): ContentInfo {
  return new ContentInfo({ schema: derDeserialize(contentInfoDer) });
}
