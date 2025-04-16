import { ContentInfo } from 'pkijs';
import { derDeserialize } from '../asn1.js';
import CmsError from './CmsError.js';
export function deserializeContentInfo(derValue) {
    try {
        const asn1Value = derDeserialize(derValue);
        return new ContentInfo({ schema: asn1Value });
    }
    catch (err) {
        throw new CmsError('Could not deserialize CMS ContentInfo', { cause: err });
    }
}
//# sourceMappingURL=utils.js.map