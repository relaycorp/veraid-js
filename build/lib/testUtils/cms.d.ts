import type { BaseBlock } from 'asn1js';
import { type PkiObject } from 'pkijs';
export declare function pkijsSerialise(pkijsValue: PkiObject): Buffer;
export declare function serializeContentInfo(content: BaseBlock<any>, contentType: string): ArrayBuffer;
