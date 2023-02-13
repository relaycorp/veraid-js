import { jest } from '@jest/globals';
import { AsnParser } from '@peculiar/asn1-schema';
import { Certificate as CertificateSchema } from '@peculiar/asn1-x509';
import { subSeconds } from 'date-fns';

import { generateMemberIdFixture } from '../../testUtils/veraStubs/memberIdFixture.js';
import { DnssecChainSchema } from '../schemas/DnssecChainSchema.js';
import { serialiseMessage } from '../../testUtils/dns.js';
import { bufferToArray } from '../utils/buffers.js';
import { selfIssueOrganisationCertificate } from '../pki/organisation.js';
import {
  ORG_DOMAIN,
  ORG_KEY_PAIR,
  ORG_KEY_SPEC,
  ORG_NAME,
} from '../../testUtils/veraStubs/organisation.js';
import { SERVICE_OID } from '../../testUtils/veraStubs/service.js';
import VeraError from '../VeraError.js';
import { DatePeriod } from '../dates.js';
import { VeraDnssecChain } from '../dns/VeraDnssecChain.js';
import { generateRsaKeyPair } from '../utils/keys/generation.js';
import { expectErrorToEqual, getPromiseRejection } from '../../testUtils/errors.js';
import CertificateError from '../utils/x509/CertificateError.js';
import { MemberIdBundleSchema } from '../schemas/MemberIdBundleSchema.js';
import Certificate from '../utils/x509/Certificate.js';
import { issueMemberCertificate } from '../pki/member.js';
import { MEMBER_KEY_PAIR, MEMBER_NAME } from '../../testUtils/veraStubs/member.js';

import { MemberIdBundle } from './MemberIdBundle.js';

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

  describe('verify', () => {
    describe('Certificate chain', () => {
      test('Member certificate should be issued by organisation certificate', async () => {
        const otherOrgCertSerialised = await selfIssueOrganisationCertificate(
          ORG_NAME,
          await generateRsaKeyPair(),
          datePeriod.end,
          { startDate: datePeriod.start },
        );
        const bundle = new MemberIdBundle(
          dnssecChain,
          AsnParser.parse(otherOrgCertSerialised, CertificateSchema),
          memberCertificateSchema,
        );

        const error = await getPromiseRejection(
          async () => bundle.verify(SERVICE_OID, datePeriod),
          VeraError,
        );

        expectErrorToEqual(
          error,
          new VeraError('Member certificate was not issued by organisation', {
            cause: expect.any(CertificateError),
          }),
        );
      });

      test('Certificates should overlap with specified period', async () => {
        const bundle = new MemberIdBundle(
          dnssecChain,
          orgCertificateSchema,
          memberCertificateSchema,
        );
        const pastPeriod = DatePeriod.init(
          subSeconds(datePeriod.start, 2),
          subSeconds(datePeriod.start, 1),
        );

        await expect(async () => bundle.verify(SERVICE_OID, pastPeriod)).rejects.toThrowWithMessage(
          VeraError,
          'Validity period of certificate chain does not overlap with required period',
        );
      });
    });

    describe('User name validation', () => {
      const errorMessage =
        'User name should not contain at signs or whitespace other than simple spaces';
      const orgCertificate = Certificate.deserialize(orgCertificateSerialised);

      async function issueInvalidMemberCertificate(userName: string): Promise<CertificateSchema> {
        const certificate = await Certificate.issue({
          commonName: userName,
          subjectPublicKey: MEMBER_KEY_PAIR.publicKey,
          issuerCertificate: orgCertificate,
          issuerPrivateKey: ORG_KEY_PAIR.privateKey,
          validityEndDate: datePeriod.end,
          validityStartDate: datePeriod.start,
        });
        const serialisation = certificate.serialize();
        return AsnParser.parse(serialisation, CertificateSchema);
      }

      test('should not contain at signs', async () => {
        const invalidMemberCertificate = await issueInvalidMemberCertificate(`@${MEMBER_NAME}`);
        const bundle = new MemberIdBundle(
          dnssecChain,
          orgCertificateSchema,
          invalidMemberCertificate,
        );

        await expect(async () =>
          bundle.verify(SERVICE_OID, datePeriod, dnssecChainFixture.trustAnchors),
        ).rejects.toThrowWithMessage(VeraError, errorMessage);
      });

      test('should not contain tabs', async () => {
        const invalidMemberCertificate = await issueInvalidMemberCertificate(`\t${MEMBER_NAME}`);
        const bundle = new MemberIdBundle(
          dnssecChain,
          orgCertificateSchema,
          invalidMemberCertificate,
        );

        await expect(async () =>
          bundle.verify(SERVICE_OID, datePeriod, dnssecChainFixture.trustAnchors),
        ).rejects.toThrowWithMessage(VeraError, errorMessage);
      });

      test('should not contain carriage returns', async () => {
        const invalidMemberCertificate = await issueInvalidMemberCertificate(`\r${MEMBER_NAME}`);
        const bundle = new MemberIdBundle(
          dnssecChain,
          orgCertificateSchema,
          invalidMemberCertificate,
        );

        await expect(async () =>
          bundle.verify(SERVICE_OID, datePeriod, dnssecChainFixture.trustAnchors),
        ).rejects.toThrowWithMessage(VeraError, errorMessage);
      });

      test('should not contain line feeds', async () => {
        const invalidMemberCertificate = await issueInvalidMemberCertificate(`\n${MEMBER_NAME}`);
        const bundle = new MemberIdBundle(
          dnssecChain,
          orgCertificateSchema,
          invalidMemberCertificate,
        );

        await expect(async () =>
          bundle.verify(SERVICE_OID, datePeriod, dnssecChainFixture.trustAnchors),
        ).rejects.toThrowWithMessage(VeraError, errorMessage);
      });
    });

    describe('DNSSEC chain', () => {
      test('Service OID should be verified', async () => {
        const bundle = new MemberIdBundle(
          dnssecChain,
          orgCertificateSchema,
          memberCertificateSchema,
        );
        const chainVerificationSpy = jest.spyOn(VeraDnssecChain.prototype, 'verify');

        await bundle.verify(SERVICE_OID, datePeriod, dnssecChainFixture.trustAnchors);

        expect(chainVerificationSpy).toHaveBeenCalledWith(
          expect.anything(),
          SERVICE_OID,
          expect.anything(),
          expect.anything(),
        );
      });

      test('Key spec should match that set in TXT rdata', async () => {
        const bundle = new MemberIdBundle(
          dnssecChain,
          orgCertificateSchema,
          memberCertificateSchema,
        );
        const chainVerificationSpy = jest.spyOn(VeraDnssecChain.prototype, 'verify');

        await bundle.verify(SERVICE_OID, datePeriod, dnssecChainFixture.trustAnchors);

        expect(chainVerificationSpy).toHaveBeenCalledWith(
          ORG_KEY_SPEC,
          expect.anything(),
          expect.anything(),
          expect.anything(),
        );
      });

      test('Date period should be intersection of specified one and the certificates', async () => {
        const bundle = new MemberIdBundle(
          dnssecChain,
          orgCertificateSchema,
          memberCertificateSchema,
        );
        const chainVerificationSpy = jest.spyOn(VeraDnssecChain.prototype, 'verify');
        const narrowPeriod = DatePeriod.init(
          subSeconds(datePeriod.start, 1),
          subSeconds(datePeriod.end, 1),
        );

        await bundle.verify(SERVICE_OID, narrowPeriod, dnssecChainFixture.trustAnchors);

        const intersection = datePeriod.intersect(narrowPeriod)!;
        expect(chainVerificationSpy).toHaveBeenCalledWith(
          expect.anything(),
          expect.anything(),
          intersection,
          expect.anything(),
        );
      });

      test('Verification errors should be propagated', async () => {
        const bundle = new MemberIdBundle(
          dnssecChain,
          orgCertificateSchema,
          memberCertificateSchema,
        );

        // Do not pass trusted anchors
        await expect(async () => bundle.verify(SERVICE_OID, datePeriod)).rejects.toThrowWithMessage(
          VeraError,
          /^Vera DNSSEC chain is BOGUS/u,
        );
      });
    });

    describe('Valid result', () => {
      test('Organisation name should be output', async () => {
        const bundle = new MemberIdBundle(
          dnssecChain,
          orgCertificateSchema,
          memberCertificateSchema,
        );

        const { organisation } = await bundle.verify(
          SERVICE_OID,
          datePeriod,
          dnssecChainFixture.trustAnchors,
        );

        expect(organisation).toStrictEqual(ORG_NAME);
      });

      test('Trailing dot should be removed from domain if present', async () => {
        const otherOrgCertificateSerialised = await selfIssueOrganisationCertificate(
          ORG_DOMAIN,
          ORG_KEY_PAIR,
          datePeriod.end,
          { startDate: datePeriod.start },
        );
        const fixture = await generateMemberIdFixture({
          datePeriod,
          orgCertificateSerialised: otherOrgCertificateSerialised,
        });
        expect(Certificate.deserialize(otherOrgCertificateSerialised).commonName).toEndWith('.');
        const bundle = new MemberIdBundle(
          dnssecChain,
          AsnParser.parse(otherOrgCertificateSerialised, CertificateSchema),
          AsnParser.parse(fixture.memberCertificateSerialised, CertificateSchema),
        );

        const { organisation } = await bundle.verify(
          SERVICE_OID,
          datePeriod,
          fixture.dnssecChainFixture.trustAnchors,
        );

        expect(organisation).toStrictEqual(ORG_NAME);
        expect(organisation).not.toEndWith('.');
      });

      test('User name should be output if member is a user', async () => {
        const bundle = new MemberIdBundle(
          dnssecChain,
          orgCertificateSchema,
          memberCertificateSchema,
        );

        const { user } = await bundle.verify(
          SERVICE_OID,
          datePeriod,
          dnssecChainFixture.trustAnchors,
        );

        expect(user).toStrictEqual(MEMBER_NAME);
      });

      test('User name should not be output if member is a bot', async () => {
        const botCertificateSerialised = await issueMemberCertificate(
          undefined,
          MEMBER_KEY_PAIR.publicKey,
          orgCertificateSerialised,
          ORG_KEY_PAIR.privateKey,
          datePeriod.end,
          { startDate: datePeriod.start },
        );
        const bundle = new MemberIdBundle(
          dnssecChain,
          orgCertificateSchema,
          AsnParser.parse(botCertificateSerialised, CertificateSchema),
        );

        const { user } = await bundle.verify(
          SERVICE_OID,
          datePeriod,
          dnssecChainFixture.trustAnchors,
        );

        expect(user).toBeUndefined();
      });
    });
  });
});
