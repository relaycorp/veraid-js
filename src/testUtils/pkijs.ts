import {
  BasicConstraints,
  type Certificate as PkijsCertificate,
  type Extension,
  type RelativeDistinguishedNames,
} from 'pkijs';

import { BASIC_CONSTRAINTS } from '../lib/oids.js';
import { derDeserialize } from '../lib/crypto_wrappers/utils.js';

import { expectAsn1ValuesToBeEqual } from './asn1.js';

type PkijsValueType = PkijsCertificate | RelativeDistinguishedNames;

export function getExtension(cert: PkijsCertificate, extensionOid: string): Extension | undefined {
  const extensions = cert.extensions!;
  return extensions.find((extension) => extension.extnID === extensionOid);
}

export function getBasicConstraintsExtension(cert: PkijsCertificate): BasicConstraints {
  const bcExtension = getExtension(cert, BASIC_CONSTRAINTS);
  const basicConstraintsAsn1 = derDeserialize(bcExtension!.extnValue.valueBlock.valueHex);
  return new BasicConstraints({ schema: basicConstraintsAsn1 });
}

export function expectPkijsValuesToBeEqual(
  expectedValue: PkijsValueType,
  actualValue: PkijsValueType,
): void {
  expectAsn1ValuesToBeEqual(expectedValue.toSchema(), actualValue.toSchema());
}
