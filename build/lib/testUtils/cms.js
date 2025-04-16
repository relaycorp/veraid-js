import { ContentInfo } from 'pkijs';
import { asn1Serialise } from './asn1.js';
export function pkijsSerialise(pkijsValue) {
    return asn1Serialise(pkijsValue.toSchema(true));
}
export function serializeContentInfo(content, contentType) {
    const contentInfo = new ContentInfo({ content, contentType });
    return contentInfo.toSchema().toBER(false);
}
//# sourceMappingURL=cms.js.map