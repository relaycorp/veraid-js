import { jest } from '@jest/globals';
import { AsnParser, AsnSerializer } from '@peculiar/asn1-schema';
import { Certificate as CertificateSchema } from '@peculiar/asn1-x509';
import { subSeconds } from 'date-fns';

import { generateMemberIdFixture } from '../../testUtils/veraStubs/memberIdFixture.js';
import { DnssecChainSchema } from '../schemas/DnssecChainSchema.js';
import { serialiseMessage } from '../../testUtils/dns.js';
import { bufferToArray } from '../utils/buffers.js';
import { selfIssueOrganisationCertificate } from '../pki/organisation.js';
import { ORG_KEY_SPEC, ORG_NAME } from '../../testUtils/veraStubs/organisation.js';
import { SERVICE_OID } from '../../testUtils/veraStubs/service.js';
import VeraError from '../VeraError.js';
import { DatePeriod } from '../dates.js';
import { VeraDnssecChain } from '../dns/VeraDnssecChain.js';
import { generateRsaKeyPair } from '../utils/keys/generation.js';
import { expectErrorToEqual, getPromiseRejection } from '../../testUtils/errors.js';
import CertificateError from '../utils/x509/CertificateError.js';
import { MemberIdBundleSchema } from '../schemas/MemberIdBundleSchema.js';

import { MemberIdBundle } from './MemberIdBundle.js';

const { orgCertificateSerialised, memberCertificateSerialised, dnssecChainFixture, datePeriod } =
  await generateMemberIdFixture();
const dnssecChain = new DnssecChainSchema(
  dnssecChainFixture.responses.map(serialiseMessage).map(bufferToArray),
);
const organisationCertificate = AsnParser.parse(orgCertificateSerialised, CertificateSchema);
const memberCertificate = AsnParser.parse(memberCertificateSerialised, CertificateSchema);

describe('MemberIdBundle', () => {
  describe('serialise', () => {
    test('Bundle should be output', () => {
      const bundle = new MemberIdBundle(dnssecChain, organisationCertificate, memberCertificate);

      const bundleSerialised = bundle.serialise();

      const expectedSchema = new MemberIdBundleSchema();
      expectedSchema.dnssecChain = dnssecChain;
      expectedSchema.organisationCertificate = organisationCertificate;
      expectedSchema.memberCertificate = memberCertificate;
      const expectedSerialisation = AsnSerializer.serialize(expectedSchema);
      expect(Buffer.from(bundleSerialised)).toStrictEqual(Buffer.from(expectedSerialisation));
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
          memberCertificate,
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
        const bundle = new MemberIdBundle(dnssecChain, organisationCertificate, memberCertificate);
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

    describe('DNSSEC chain', () => {
      test('Service OID should be verified', async () => {
        const bundle = new MemberIdBundle(dnssecChain, organisationCertificate, memberCertificate);
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
        const bundle = new MemberIdBundle(dnssecChain, organisationCertificate, memberCertificate);
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
        const bundle = new MemberIdBundle(dnssecChain, organisationCertificate, memberCertificate);
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
        const bundle = new MemberIdBundle(dnssecChain, organisationCertificate, memberCertificate);

        // Do not pass trusted anchors
        await expect(async () => bundle.verify(SERVICE_OID, datePeriod)).rejects.toThrowWithMessage(
          VeraError,
          /^Vera DNSSEC chain is BOGUS/u,
        );
      });
    });

    test('Valid bundle should be reported as such', async () => {
      const bundle = new MemberIdBundle(dnssecChain, organisationCertificate, memberCertificate);

      await expect(
        bundle.verify(SERVICE_OID, datePeriod, dnssecChainFixture.trustAnchors),
      ).toResolve();
    });
  });
});
