import type { IBerConvertible } from 'asn1js';
export declare function asn1Serialise(asn1Value: IBerConvertible): Buffer;
export declare function expectAsn1ValuesToBeEqual(expectedValue: IBerConvertible, actualValue: IBerConvertible): void;
