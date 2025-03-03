import { AsnParser, AsnSerializer } from '@peculiar/asn1-schema';
import { Certificate as CertificateSchema } from '@peculiar/asn1-x509';

import { generateMemberIdFixture } from '../../testUtils/veraStubs/memberIdFixture.js';
import { MEMBER_KEY_PAIR, MEMBER_NAME } from '../../testUtils/veraStubs/member.js';
import { ORG_KEY_PAIR } from '../../testUtils/veraStubs/organisation.js';
import { serialiseMessage } from '../../testUtils/dns.js';
import { arrayBufferFrom } from '../../testUtils/buffers.js';
import { bufferToArray } from '../utils/buffers.js';
import { DnssecChainSchema } from '../schemas/DnssecChainSchema.js';
import { MemberIdBundleSchema } from '../schemas/MemberIdBundleSchema.js';
import { issueMemberCertificate } from '../pki/member.js';
import VeraidError from '../VeraidError.js';

import { MemberIdBundle } from './MemberIdBundle.js';
import { serialiseMemberIdBundle } from './serialisation.js';

const { orgCertificateSerialised, memberCertificateSerialised, dnssecChainFixture, datePeriod } =
  await generateMemberIdFixture();
const dnssecChain = new DnssecChainSchema(
  dnssecChainFixture.responses.map(serialiseMessage).map(bufferToArray),
);
const orgCertificateSchema = AsnParser.parse(orgCertificateSerialised, CertificateSchema);
const memberCertificateSchema = AsnParser.parse(memberCertificateSerialised, CertificateSchema);

describe('MemberIdBundle', () => {
  describe('serialise', () => {
    test('Version should be 0', () => {
      const bundle = new MemberIdBundle(dnssecChain, orgCertificateSchema, memberCertificateSchema);

      const serialisation = bundle.serialise();

      const bundleDeserialised = AsnParser.parse(serialisation, MemberIdBundleSchema);
      expect(bundleDeserialised.version).toBe(0);
    });

    test('DNSSEC chain should be included', () => {
      const bundle = new MemberIdBundle(dnssecChain, orgCertificateSchema, memberCertificateSchema);

      const serialisation = bundle.serialise();

      const bundleDeserialised = AsnParser.parse(serialisation, MemberIdBundleSchema);
      expect(bundleDeserialised.dnssecChain.map((message) => Buffer.from(message))).toStrictEqual(
        dnssecChain.map((message) => Buffer.from(message)),
      );
    });

    test('Organisation certificate should be included', () => {
      const bundle = new MemberIdBundle(dnssecChain, orgCertificateSchema, memberCertificateSchema);

      const serialisation = bundle.serialise();

      const bundleDeserialised = AsnParser.parse(serialisation, MemberIdBundleSchema);
      expect(bundleDeserialised.organisationCertificate).toStrictEqual(orgCertificateSchema);
    });

    test('Member certificate should be included', () => {
      const bundle = new MemberIdBundle(dnssecChain, orgCertificateSchema, memberCertificateSchema);

      const serialisation = bundle.serialise();

      const bundleDeserialised = AsnParser.parse(serialisation, MemberIdBundleSchema);
      expect(bundleDeserialised.memberCertificate).toStrictEqual(memberCertificateSchema);
    });
  });

  describe('signerCertificateSchema', () => {
    test('should return the member certificate schema', () => {
      const bundle = new MemberIdBundle(dnssecChain, orgCertificateSchema, memberCertificateSchema);

      // Access the public getter directly using destructuring
      const { signerCertificateSchema } = bundle;

      expect(signerCertificateSchema).toBe(memberCertificateSchema);
    });
  });

  describe('signerName', () => {
    test('should return the member name if not a bot', () => {
      const bundle = new MemberIdBundle(dnssecChain, orgCertificateSchema, memberCertificateSchema);

      // Access the public getter directly using destructuring
      const { signerName } = bundle;

      expect(signerName).toBe(MEMBER_NAME);
    });

    test('should return undefined if member is a bot', async () => {
      const botCertificateSerialised = await issueMemberCertificate(
        undefined,
        MEMBER_KEY_PAIR.publicKey,
        orgCertificateSerialised,
        ORG_KEY_PAIR.privateKey,
        datePeriod.end,
        { startDate: datePeriod.start },
      );
      const botCertificateSchema = AsnParser.parse(botCertificateSerialised, CertificateSchema);
      const bundle = new MemberIdBundle(dnssecChain, orgCertificateSchema, botCertificateSchema);

      // Access the public getter directly using destructuring
      const { signerName } = bundle;

      expect(signerName).toBeUndefined();
    });
  });

  describe('deserialise', () => {
    test('Malformed member Id bundle should be refused', () => {
      const malformedBundle = arrayBufferFrom('malformed');

      expect(() => MemberIdBundle.deserialise(malformedBundle)).toThrowWithMessage(
        VeraidError,
        'Member id bundle is malformed',
      );
    });

    test('Should create a MemberIdBundle instance from serialized data', async () => {
      const fixture = await generateMemberIdFixture();
      const fixtureOrgCertSerialised = fixture.orgCertificateSerialised;
      const fixtureMemberCertSerialised = fixture.memberCertificateSerialised;
      const fixtureDnssecChain = fixture.dnssecChainFixture;

      const dnssecChainSerialised = AsnSerializer.serialize(
        new DnssecChainSchema(
          fixtureDnssecChain.responses.map(serialiseMessage).map(bufferToArray),
        ),
      );

      const memberIdBundle = serialiseMemberIdBundle(
        fixtureMemberCertSerialised,
        fixtureOrgCertSerialised,
        dnssecChainSerialised,
      );

      const bundle = MemberIdBundle.deserialise(memberIdBundle);

      expect(bundle).toBeInstanceOf(MemberIdBundle);
      expect(Buffer.from(bundle.serialise())).toStrictEqual(Buffer.from(memberIdBundle));
    });
  });
});
