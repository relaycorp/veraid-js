import type { BaseBlock, IBerConvertible } from 'asn1js';
import { ContentInfo, type PkiObject } from 'pkijs';

import { asn1Serialise } from './asn1.js';

export function pkijsSerialise(pkijsValue: PkiObject): Buffer {
  return asn1Serialise(pkijsValue.toSchema(true) as IBerConvertible);
}

export function serializeContentInfo(content: BaseBlock<any>, contentType: string): ArrayBuffer {
  const contentInfo = new ContentInfo({ content, contentType });
  return contentInfo.toSchema().toBER(false);
}
