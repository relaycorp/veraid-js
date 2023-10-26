import { Certificate as CertificateSchema } from '@peculiar/asn1-x509';
import { AsnParser } from '@peculiar/asn1-schema';

import VeraidError from '../VeraidError.js';
import { DnssecChainSchema } from '../schemas/DnssecChainSchema.js';

import { MemberIdBundle } from './MemberIdBundle.js';

export function serialiseMemberIdBundle(
  memberCertificateSerialised: ArrayBuffer,
  orgCertificateSerialised: ArrayBuffer,
  dnssecChainSerialised: ArrayBuffer,
): ArrayBuffer {
  let memberCertificate: CertificateSchema;
  try {
    memberCertificate = AsnParser.parse(memberCertificateSerialised, CertificateSchema);
  } catch (err) {
    throw new VeraidError('Member certificate is malformed', { cause: err });
  }

  let orgCertificate: CertificateSchema;
  try {
    orgCertificate = AsnParser.parse(orgCertificateSerialised, CertificateSchema);
  } catch (err) {
    throw new VeraidError('Organisation certificate is malformed', { cause: err });
  }

  let dnssecChain: DnssecChainSchema;
  try {
    dnssecChain = AsnParser.parse(dnssecChainSerialised, DnssecChainSchema);
  } catch (err) {
    throw new VeraidError('DNSSEC chain is malformed', { cause: err });
  }

  const bundle = new MemberIdBundle(dnssecChain, orgCertificate, memberCertificate);
  return bundle.serialise();
}
