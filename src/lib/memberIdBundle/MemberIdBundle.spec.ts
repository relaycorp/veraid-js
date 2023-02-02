import { AsnParser, AsnSerializer } from '@peculiar/asn1-schema';
import { Certificate as CertificateSchema } from '@peculiar/asn1-x509';

import { generateMemberIdFixture } from '../../testUtils/veraStubs/memberIdFixture.js';
import { DnssecChainSchema } from '../dns/DnssecChainSchema.js';
import { serialiseMessage } from '../../testUtils/dns.js';
import { bufferToArray } from '../utils/buffers.js';

import { MemberIdBundleSchema } from './MemberIdBundleSchema.js';
import { MemberIdBundle } from './MemberIdBundle.js';

const { organisationCertificate, memberCertificate, veraDnssecChain } =
  await generateMemberIdFixture();

describe('MemberIdBundle', () => {
  describe('serialise', () => {
    test('Bundle should be output', () => {
      const dnssecChain = new DnssecChainSchema(
        veraDnssecChain.responses.map(serialiseMessage).map(bufferToArray),
      );
      const bundle = new MemberIdBundle(
        dnssecChain,
        AsnParser.parse(organisationCertificate, CertificateSchema),
        AsnParser.parse(memberCertificate, CertificateSchema),
      );

      const bundleSerialised = bundle.serialise();

      const bundleSchema = AsnParser.parse(bundleSerialised, MemberIdBundleSchema);
      expect(Buffer.from(AsnSerializer.serialize(bundleSchema.dnssecChain))).toStrictEqual(
        Buffer.from(AsnSerializer.serialize(dnssecChain)),
      );
      expect(
        Buffer.from(AsnSerializer.serialize(bundleSchema.organisationCertificate)),
      ).toStrictEqual(Buffer.from(organisationCertificate));
      expect(Buffer.from(AsnSerializer.serialize(bundleSchema.memberCertificate))).toStrictEqual(
        Buffer.from(memberCertificate),
      );
    });
  });
});
