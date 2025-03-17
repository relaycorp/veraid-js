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

import { MemberIdBundle } from './MemberIdBundle.js';

const { orgCertificate, memberCertificate, dnssecChainFixture, datePeriod } =
  await generateMemberIdFixture();
const VERAID_DNSSEC_CHAIN = new VeraidDnssecChain(
  orgCertificate.commonName,
  dnssecChainFixture.responses.map(serialiseMessage).map(bufferToArray),
);

describe('MemberIdBundle', () => {
  describe('toSchema', () => {
    test('should output ASN.1 schema', () => {
      const bundle = new MemberIdBundle(VERAID_DNSSEC_CHAIN, orgCertificate, memberCertificate);

      const schema = bundle.toSchema();

      const schemaBuffer = Buffer.from(AsnSerializer.serialize(schema));
      const serializedBuffer = Buffer.from(bundle.serialise());
      expect(schemaBuffer).toStrictEqual(serializedBuffer);
    });
  });

  describe('fromSchema', () => {
    test('should create instance from valid schema', () => {
      const bundle = new MemberIdBundle(VERAID_DNSSEC_CHAIN, orgCertificate, memberCertificate);
      const schema = bundle.toSchema();

      const bundleFromSchema = MemberIdBundle.fromSchema(schema);

      expect(Buffer.from(bundleFromSchema.serialise())).toStrictEqual(
        Buffer.from(bundle.serialise()),
      );
    });
  });

  describe('serialise', () => {
    test('Version should be 0', () => {
      const bundle = new MemberIdBundle(VERAID_DNSSEC_CHAIN, orgCertificate, memberCertificate);

      const serialisation = bundle.serialise();

      const bundleDeserialised = AsnParser.parse(serialisation, MemberIdBundleSchema);
      expect(bundleDeserialised.version).toBe(0);
    });

    test('DNSSEC chain should be included', () => {
      const bundle = new MemberIdBundle(VERAID_DNSSEC_CHAIN, orgCertificate, memberCertificate);

      const serialisation = bundle.serialise();

      const bundleDeserialised = AsnParser.parse(serialisation, MemberIdBundleSchema);
      const dnssecChainSerialised = AsnSerializer.serialize(bundleDeserialised.dnssecChain);
      expect(Buffer.from(dnssecChainSerialised)).toStrictEqual(
        Buffer.from(VERAID_DNSSEC_CHAIN.serialise()),
      );
    });

    test('Organisation certificate should be included', () => {
      const bundle = new MemberIdBundle(VERAID_DNSSEC_CHAIN, orgCertificate, memberCertificate);

      const serialisation = bundle.serialise();

      const bundleDeserialised = AsnParser.parse(serialisation, MemberIdBundleSchema);
      expect(bundleDeserialised.organisationCertificate).toStrictEqual(orgCertificate.toSchema());
    });

    test('Member certificate should be included', () => {
      const bundle = new MemberIdBundle(VERAID_DNSSEC_CHAIN, orgCertificate, memberCertificate);

      const serialisation = bundle.serialise();

      const bundleDeserialised = AsnParser.parse(serialisation, MemberIdBundleSchema);
      expect(bundleDeserialised.memberCertificate).toStrictEqual(memberCertificate.toSchema());
    });
  });

  describe('signerCertificate', () => {
    test('should return the member certificate', () => {
      const bundle = new MemberIdBundle(VERAID_DNSSEC_CHAIN, orgCertificate, memberCertificate);

      const { signerCertificate } = bundle;

      expect(signerCertificate).toBe(memberCertificate);
    });
  });

  describe('signerName', () => {
    test('should return the member name if not a bot', () => {
      const bundle = new MemberIdBundle(VERAID_DNSSEC_CHAIN, orgCertificate, memberCertificate);

      const { signerName } = bundle;

      expect(signerName).toBe(MEMBER_NAME);
    });

    test('should return undefined if member is a bot', async () => {
      const botCertificate = await issueMemberCertificate(
        undefined,
        MEMBER_KEY_PAIR.publicKey,
        orgCertificate,
        ORG_KEY_PAIR.privateKey,
        datePeriod.end,
        { startDate: datePeriod.start },
      );
      const bundle = new MemberIdBundle(VERAID_DNSSEC_CHAIN, orgCertificate, botCertificate);

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

    test('should deserialise valid bundle', () => {
      const dnssecChain = new VeraidDnssecChain(
        orgCertificate.commonName,
        new DnssecChainSchema(
          dnssecChainFixture.responses.map(serialiseMessage).map(bufferToArray),
        ),
      );
      const bundle = new MemberIdBundle(dnssecChain, orgCertificate, memberCertificate);
      const bundleSerialised = bundle.serialise();

      const deserializedBundle = MemberIdBundle.deserialise(bundleSerialised);

      expect(Buffer.from(deserializedBundle.serialise())).toStrictEqual(
        Buffer.from(bundleSerialised),
      );
    });
  });
});
