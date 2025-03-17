import { AsnParser } from '@peculiar/asn1-schema';

import VeraidError from '../VeraidError.js';
import { DnssecChainSchema } from '../schemas/DnssecChainSchema.js';
import Certificate from '../utils/x509/Certificate.js';
import { VeraidDnssecChain } from '../dns/VeraidDnssecChain.js';

import { MemberIdBundle } from './MemberIdBundle.js';

export function serialiseMemberIdBundle(
  memberCertificateSerialised: ArrayBuffer,
  orgCertificateSerialised: ArrayBuffer,
  dnssecChainSerialised: ArrayBuffer,
): ArrayBuffer {
  let memberCertificate: Certificate;
  try {
    memberCertificate = Certificate.deserialize(memberCertificateSerialised);
  } catch (err) {
    throw new VeraidError('Member certificate is malformed', { cause: err });
  }

  let orgCertificate: Certificate;
  try {
    orgCertificate = Certificate.deserialize(orgCertificateSerialised);
  } catch (err) {
    throw new VeraidError('Organisation certificate is malformed', { cause: err });
  }

  let dnssecChainSchema: DnssecChainSchema;
  try {
    dnssecChainSchema = AsnParser.parse(dnssecChainSerialised, DnssecChainSchema);
  } catch (err) {
    throw new VeraidError('DNSSEC chain is malformed', { cause: err });
  }

  const dnssecChain = new VeraidDnssecChain(orgCertificate.commonName, dnssecChainSchema);
  const bundle = new MemberIdBundle(dnssecChain, orgCertificate, memberCertificate);
  return bundle.serialise();
}
