import { BasicConstraints, } from 'pkijs';
import { BASIC_CONSTRAINTS } from '../lib/oids.js';
import { derDeserialize } from '../lib/utils/asn1.js';
import { expectAsn1ValuesToBeEqual } from './asn1.js';
export function getExtension(cert, extensionOid) {
    const extensions = cert.extensions;
    return extensions.find((extension) => extension.extnID === extensionOid);
}
export function getBasicConstraintsExtension(cert) {
    const bcExtension = getExtension(cert, BASIC_CONSTRAINTS);
    const basicConstraintsAsn1 = derDeserialize(bcExtension.extnValue.valueBlock.valueHexView);
    return new BasicConstraints({ schema: basicConstraintsAsn1 });
}
export function expectPkijsValuesToBeEqual(expectedValue, actualValue) {
    expectAsn1ValuesToBeEqual(expectedValue.toSchema(), actualValue.toSchema());
}
//# sourceMappingURL=pkijs.js.map