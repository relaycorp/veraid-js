import { Certificate as CertificateSchema } from '@peculiar/asn1-x509';
import { AsnParser, AsnSerializer } from '@peculiar/asn1-schema';

import VeraError from '../VeraError.js';
import { DnssecChain } from '../dns/DnssecChain.js';

import { MemberIdBundleSchema } from './MemberIdBundleSchema.js';

export function serialiseMemberIdBundle(
  memberCertificateSerialised: ArrayBuffer,
  orgCertificateSerialised: ArrayBuffer,
  dnssecChainSerialised: ArrayBuffer,
): ArrayBuffer {
  let memberCertificate: CertificateSchema;
  try {
    memberCertificate = AsnParser.parse(memberCertificateSerialised, CertificateSchema);
  } catch (err) {
    throw new VeraError('Member certificate is malformed', { cause: err });
  }

  let orgCertificate: CertificateSchema;
  try {
    orgCertificate = AsnParser.parse(orgCertificateSerialised, CertificateSchema);
  } catch (err) {
    throw new VeraError('Organisation certificate is malformed', { cause: err });
  }

  let dnssecChain: DnssecChain;
  try {
    dnssecChain = AsnParser.parse(dnssecChainSerialised, DnssecChain);
  } catch (err) {
    throw new VeraError('DNSSEC chain is malformed', { cause: err });
  }

  const bundle = new MemberIdBundleSchema();
  bundle.memberCertificate = memberCertificate;
  bundle.organisationCertificate = orgCertificate;
  bundle.dnssecChain = dnssecChain;
  return AsnSerializer.serialize(bundle);
}
