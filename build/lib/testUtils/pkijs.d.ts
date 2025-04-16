import { BasicConstraints, type Certificate as PkijsCertificate, type Extension, type RelativeDistinguishedNames } from 'pkijs';
type PkijsValueType = PkijsCertificate | RelativeDistinguishedNames;
export declare function getExtension(cert: PkijsCertificate, extensionOid: string): Extension | undefined;
export declare function getBasicConstraintsExtension(cert: PkijsCertificate): BasicConstraints;
export declare function expectPkijsValuesToBeEqual(expectedValue: PkijsValueType, actualValue: PkijsValueType): void;
export {};
