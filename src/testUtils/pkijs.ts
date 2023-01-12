import {
  BasicConstraints,
  type Certificate as PkijsCertificate,
  type Extension,
  type RelativeDistinguishedNames,
} from 'pkijs';

import { BASIC_CONSTRAINTS } from '../lib/oids.js';
import { derDeserialize } from '../lib/utils/asn1.js';
import Certificate from '../lib/utils/x509/Certificate.js';

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

export function reSerializeCertificate(cert: Certificate): Certificate {
  // TODO: Raise bug in PKI.js project
  // PKI.js sometimes tries to use attributes that are only set *after* the certificate has been
  // deserialized, so you'd get a TypeError if you use a certificate you just created in memory.
  // For example, `extension.parsedValue` would be `undefined` in
  // https://github.com/PeculiarVentures/PKI.js/blob/9a39551aa9f1445406f96680318014c8d714e8e3/src/CertificateChainValidationEngine.js#L155
  return Certificate.deserialize(cert.serialize());
}
