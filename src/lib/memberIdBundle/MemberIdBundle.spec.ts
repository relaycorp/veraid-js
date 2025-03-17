import { AsnParser, AsnSerializer } from '@peculiar/asn1-schema';

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
import { VeraidDnssecChain } from '../dns/VeraidDnssecChain.js';
import Certificate from '../utils/x509/Certificate.js';

import { MemberIdBundle } from './MemberIdBundle.js';
import { serialiseMemberIdBundle } from './serialisation.js';

const { orgCertificateSerialised, memberCertificateSerialised, dnssecChainFixture, datePeriod } =
  await generateMemberIdFixture();
const ORG_CERTIFICATE = Certificate.deserialize(orgCertificateSerialised);
const MEMBER_CERTIFICATE = Certificate.deserialize(memberCertificateSerialised);
const VERAID_DNSSEC_CHAIN = new VeraidDnssecChain(
  ORG_CERTIFICATE.commonName,
  dnssecChainFixture.responses.map(serialiseMessage).map(bufferToArray),
);

describe('MemberIdBundle', () => {
  describe('toSchema', () => {
    test('should output ASN.1 schema', () => {
      const bundle = new MemberIdBundle(VERAID_DNSSEC_CHAIN, ORG_CERTIFICATE, MEMBER_CERTIFICATE);

      const schema = bundle.toSchema();

      const schemaBuffer = Buffer.from(AsnSerializer.serialize(schema));
      const serializedBuffer = Buffer.from(bundle.serialise());
      expect(schemaBuffer).toStrictEqual(serializedBuffer);
    });
  });

  describe('fromSchema', () => {
    test('should create instance from valid schema', () => {
      const bundle = new MemberIdBundle(VERAID_DNSSEC_CHAIN, ORG_CERTIFICATE, MEMBER_CERTIFICATE);
      const schema = bundle.toSchema();

      const bundleFromSchema = MemberIdBundle.fromSchema(schema);

      expect(Buffer.from(bundleFromSchema.serialise())).toStrictEqual(
        Buffer.from(bundle.serialise()),
      );
    });
  });

  describe('serialise', () => {
    test('Version should be 0', () => {
      const bundle = new MemberIdBundle(VERAID_DNSSEC_CHAIN, ORG_CERTIFICATE, MEMBER_CERTIFICATE);

      const serialisation = bundle.serialise();

      const bundleDeserialised = AsnParser.parse(serialisation, MemberIdBundleSchema);
      expect(bundleDeserialised.version).toBe(0);
    });

    test('DNSSEC chain should be included', () => {
      const bundle = new MemberIdBundle(VERAID_DNSSEC_CHAIN, ORG_CERTIFICATE, MEMBER_CERTIFICATE);

      const serialisation = bundle.serialise();

      const bundleDeserialised = AsnParser.parse(serialisation, MemberIdBundleSchema);
      const dnssecChainSerialised = AsnSerializer.serialize(bundleDeserialised.dnssecChain);
      expect(Buffer.from(dnssecChainSerialised)).toStrictEqual(
        Buffer.from(VERAID_DNSSEC_CHAIN.serialise()),
      );
    });

    test('Organisation certificate should be included', () => {
      const bundle = new MemberIdBundle(VERAID_DNSSEC_CHAIN, ORG_CERTIFICATE, MEMBER_CERTIFICATE);

      const serialisation = bundle.serialise();

      const bundleDeserialised = AsnParser.parse(serialisation, MemberIdBundleSchema);
      expect(bundleDeserialised.organisationCertificate).toStrictEqual(ORG_CERTIFICATE.toSchema());
    });

    test('Member certificate should be included', () => {
      const bundle = new MemberIdBundle(VERAID_DNSSEC_CHAIN, ORG_CERTIFICATE, MEMBER_CERTIFICATE);

      const serialisation = bundle.serialise();

      const bundleDeserialised = AsnParser.parse(serialisation, MemberIdBundleSchema);
      expect(bundleDeserialised.memberCertificate).toStrictEqual(MEMBER_CERTIFICATE.toSchema());
    });
  });

  describe('signerCertificate', () => {
    test('should return the member certificate', () => {
      const bundle = new MemberIdBundle(VERAID_DNSSEC_CHAIN, ORG_CERTIFICATE, MEMBER_CERTIFICATE);

      const { signerCertificate } = bundle;

      expect(signerCertificate).toBe(MEMBER_CERTIFICATE);
    });
  });

  describe('signerName', () => {
    test('should return the member name if not a bot', () => {
      const bundle = new MemberIdBundle(VERAID_DNSSEC_CHAIN, ORG_CERTIFICATE, MEMBER_CERTIFICATE);

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
      const botCertificate = Certificate.deserialize(botCertificateSerialised);
      const bundle = new MemberIdBundle(VERAID_DNSSEC_CHAIN, ORG_CERTIFICATE, botCertificate);

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
