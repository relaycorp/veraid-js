import { jest } from '@jest/globals';
import { subSeconds } from 'date-fns';

import { expectErrorToEqual, getPromiseRejection } from '../testUtils/errors.js';
import { serialiseMessage } from '../testUtils/dns.js';
import { generateMemberIdFixture } from '../testUtils/veraStubs/memberIdFixture.js';
import { MEMBER_NAME } from '../testUtils/veraStubs/member.js';
import {
  ORG_NAME,
  ORG_DOMAIN,
  ORG_KEY_PAIR,
  ORG_KEY_SPEC,
} from '../testUtils/veraStubs/organisation.js';
import { SERVICE_OID } from '../testUtils/veraStubs/service.js';

import { bufferToArray } from './utils/buffers.js';
import type { Certificate } from './utils/x509/Certificate.js';
import CertificateError from './utils/x509/CertificateError.js';
import { generateRsaKeyPair } from './utils/keys/generation.js';
import { Chain } from './Chain.js';
import { DatePeriod } from './dates.js';
import { selfIssueOrganisationCertificate } from './pki/organisation.js';
import { VeraidDnssecChain } from './dns/VeraidDnssecChain.js';
import { VeraidError } from './VeraidError.js';

const { orgCertificate, memberCertificate, dnssecChainFixture, datePeriod } =
  await generateMemberIdFixture();
const VERAID_DNSSEC_CHAIN = new VeraidDnssecChain(
  orgCertificate.commonName,
  dnssecChainFixture.responses.map(serialiseMessage).map(bufferToArray),
);

class StubChain extends Chain {
  public constructor(
    veraidDnssecChain: VeraidDnssecChain,
    organisationCertificate: Certificate,
    protected readonly signerCertificateValue: Certificate | undefined,
    public readonly signerNameValue?: string,
  ) {
    super(veraidDnssecChain, organisationCertificate);
  }

  public override get signerCertificate() {
    return this.signerCertificateValue;
  }

  public override get signerName() {
    return this.signerNameValue;
  }
}

describe('Chain', () => {
  describe('verify', () => {
    describe('Certificate chain', () => {
      test('Signer certificate should be issued by organisation certificate', async () => {
        const otherOrgCertificate = await selfIssueOrganisationCertificate(
          ORG_NAME,
          await generateRsaKeyPair(),
          datePeriod.end,
          { startDate: datePeriod.start },
        );
        const otherDnssecChain = new VeraidDnssecChain(
          otherOrgCertificate.commonName,
          dnssecChainFixture.responses.map(serialiseMessage).map(bufferToArray),
        );
        const chain = new StubChain(otherDnssecChain, otherOrgCertificate, memberCertificate);

        const error = await getPromiseRejection(
          async () => chain.verify(SERVICE_OID, datePeriod),
          VeraidError,
        );

        expectErrorToEqual(
          error,
          new VeraidError('Member certificate was not issued by organisation', {
            cause: expect.any(CertificateError),
          }),
        );
      });

      test('Should reuse orgCertificate when signerCertificateSchema is undefined', async () => {
        const chain = new StubChain(VERAID_DNSSEC_CHAIN, orgCertificate, undefined);

        // This should succeed because the orgCertificate will be used as both
        // the org and signer certificate
        const result = await chain.verify(SERVICE_OID, datePeriod, dnssecChainFixture.trustAnchors);

        expect(result.organisation).toStrictEqual(ORG_NAME);
      });

      test('Certificates should overlap with specified period', async () => {
        const chain = new StubChain(VERAID_DNSSEC_CHAIN, orgCertificate, memberCertificate);
        const pastPeriod = DatePeriod.init(
          subSeconds(datePeriod.start, 2),
          subSeconds(datePeriod.start, 1),
        );

        await expect(async () => chain.verify(SERVICE_OID, pastPeriod)).rejects.toThrowWithMessage(
          VeraidError,
          `Validity period of certificate chain (${datePeriod.toString()}) ` +
            `does not overlap with required period (${pastPeriod.toString()})`,
        );
      });
    });

    describe('User name validation', () => {
      const errorMessage =
        'User name should not contain at signs or whitespace other than simple spaces';

      test('should not contain at signs', async () => {
        const invalidSignerName = `@${MEMBER_NAME}`;
        const chain = new StubChain(
          VERAID_DNSSEC_CHAIN,
          orgCertificate,
          memberCertificate,
          invalidSignerName,
        );

        await expect(async () =>
          chain.verify(SERVICE_OID, datePeriod, dnssecChainFixture.trustAnchors),
        ).rejects.toThrowWithMessage(VeraidError, errorMessage);
      });

      test('should not contain tabs', async () => {
        const invalidSignerName = `\t${MEMBER_NAME}`;
        const chain = new StubChain(
          VERAID_DNSSEC_CHAIN,
          orgCertificate,
          memberCertificate,
          invalidSignerName,
        );

        await expect(async () =>
          chain.verify(SERVICE_OID, datePeriod, dnssecChainFixture.trustAnchors),
        ).rejects.toThrowWithMessage(VeraidError, errorMessage);
      });

      test('should not contain carriage returns', async () => {
        const invalidSignerName = `\r${MEMBER_NAME}`;
        const chain = new StubChain(
          VERAID_DNSSEC_CHAIN,
          orgCertificate,
          memberCertificate,
          invalidSignerName,
        );

        await expect(async () =>
          chain.verify(SERVICE_OID, datePeriod, dnssecChainFixture.trustAnchors),
        ).rejects.toThrowWithMessage(VeraidError, errorMessage);
      });

      test('should not contain line feeds', async () => {
        const invalidSignerName = `\n${MEMBER_NAME}`;
        const chain = new StubChain(
          VERAID_DNSSEC_CHAIN,
          orgCertificate,
          memberCertificate,
          invalidSignerName,
        );

        await expect(async () =>
          chain.verify(SERVICE_OID, datePeriod, dnssecChainFixture.trustAnchors),
        ).rejects.toThrowWithMessage(VeraidError, errorMessage);
      });
    });

    describe('DNSSEC chain', () => {
      test('Service OID should be verified', async () => {
        const chain = new StubChain(VERAID_DNSSEC_CHAIN, orgCertificate, memberCertificate);
        const chainVerificationSpy = jest.spyOn(VeraidDnssecChain.prototype, 'verify');

        await chain.verify(SERVICE_OID, datePeriod, dnssecChainFixture.trustAnchors);

        expect(chainVerificationSpy).toHaveBeenCalledWith(
          expect.anything(),
          SERVICE_OID,
          expect.anything(),
          expect.anything(),
        );
      });

      test('Key spec should match that set in TXT rdata', async () => {
        const chain = new StubChain(VERAID_DNSSEC_CHAIN, orgCertificate, memberCertificate);
        const chainVerificationSpy = jest.spyOn(VeraidDnssecChain.prototype, 'verify');

        await chain.verify(SERVICE_OID, datePeriod, dnssecChainFixture.trustAnchors);

        expect(chainVerificationSpy).toHaveBeenCalledWith(
          ORG_KEY_SPEC,
          expect.anything(),
          expect.anything(),
          expect.anything(),
        );
      });

      test('Date period should be intersection of specified one and the certificates', async () => {
        const chain = new StubChain(VERAID_DNSSEC_CHAIN, orgCertificate, memberCertificate);
        const chainVerificationSpy = jest.spyOn(VeraidDnssecChain.prototype, 'verify');
        const narrowPeriod = DatePeriod.init(
          subSeconds(datePeriod.start, 1),
          subSeconds(datePeriod.end, 1),
        );

        await chain.verify(SERVICE_OID, narrowPeriod, dnssecChainFixture.trustAnchors);

        const intersection = datePeriod.intersect(narrowPeriod)!;
        expect(chainVerificationSpy).toHaveBeenCalledWith(
          expect.anything(),
          expect.anything(),
          intersection,
          expect.anything(),
        );
      });

      test('Verification errors should be propagated', async () => {
        const chain = new StubChain(VERAID_DNSSEC_CHAIN, orgCertificate, memberCertificate);

        // Do not pass trusted anchors
        await expect(async () => chain.verify(SERVICE_OID, datePeriod)).rejects.toThrowWithMessage(
          VeraidError,
          /^VeraId DNSSEC chain is BOGUS/u,
        );
      });
    });

    describe('Valid result', () => {
      test('Organisation name should be output', async () => {
        const chain = new StubChain(VERAID_DNSSEC_CHAIN, orgCertificate, memberCertificate);

        const { organisation } = await chain.verify(
          SERVICE_OID,
          datePeriod,
          dnssecChainFixture.trustAnchors,
        );

        expect(organisation).toStrictEqual(ORG_NAME);
      });

      test('Trailing dot should be removed from domain if present', async () => {
        const otherOrgCertificate = await selfIssueOrganisationCertificate(
          ORG_DOMAIN,
          ORG_KEY_PAIR,
          datePeriod.end,
          { startDate: datePeriod.start },
        );
        const fixture = await generateMemberIdFixture({
          datePeriod,
          orgCertificate: otherOrgCertificate,
        });
        expect(otherOrgCertificate.commonName).toEndWith('.');
        const chain = new StubChain(
          VERAID_DNSSEC_CHAIN,
          otherOrgCertificate,
          fixture.memberCertificate,
        );

        const { organisation } = await chain.verify(
          SERVICE_OID,
          datePeriod,
          fixture.dnssecChainFixture.trustAnchors,
        );

        expect(organisation).toStrictEqual(ORG_NAME);
        expect(organisation).not.toEndWith('.');
      });

      test('User name should be output if provided', async () => {
        const chain = new StubChain(
          VERAID_DNSSEC_CHAIN,
          orgCertificate,
          memberCertificate,
          MEMBER_NAME,
        );

        const { user } = await chain.verify(
          SERVICE_OID,
          datePeriod,
          dnssecChainFixture.trustAnchors,
        );

        expect(user).toStrictEqual(MEMBER_NAME);
      });

      test('User name should not be output if not provided', async () => {
        const chain = new StubChain(VERAID_DNSSEC_CHAIN, orgCertificate, memberCertificate);

        const { user } = await chain.verify(
          SERVICE_OID,
          datePeriod,
          dnssecChainFixture.trustAnchors,
        );

        expect(user).toBeUndefined();
      });
    });
  });
});
