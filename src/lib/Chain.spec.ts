import { jest } from '@jest/globals';
import { AsnParser } from '@peculiar/asn1-schema';
import { Certificate as CertificateSchema } from '@peculiar/asn1-x509';
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
import Certificate from './utils/x509/Certificate.js';
import CertificateError from './utils/x509/CertificateError.js';
import { generateRsaKeyPair } from './utils/keys/generation.js';
import { Chain } from './Chain.js';
import { DatePeriod } from './dates.js';
import { DnssecChainSchema } from './schemas/DnssecChainSchema.js';
import { selfIssueOrganisationCertificate } from './pki/organisation.js';
import { VeraidDnssecChain } from './dns/VeraidDnssecChain.js';
import VeraidError from './VeraidError.js';

const { orgCertificateSerialised, memberCertificateSerialised, dnssecChainFixture, datePeriod } =
  await generateMemberIdFixture();
const dnssecChain = new DnssecChainSchema(
  dnssecChainFixture.responses.map(serialiseMessage).map(bufferToArray),
);
const ORG_CERT_SCHEMA = AsnParser.parse(orgCertificateSerialised, CertificateSchema);
const MEMBER_CERT_SCHEMA = AsnParser.parse(memberCertificateSerialised, CertificateSchema);

class StubChain extends Chain {
  public constructor(
    dnssecChainSchema: DnssecChainSchema,
    orgCertificateSchema: CertificateSchema,
    public readonly signerCertificateSchemaValue: CertificateSchema | undefined,
    public readonly signerNameValue?: string,
  ) {
    super(dnssecChainSchema, orgCertificateSchema);
  }

  public override get signerCertificateSchema() {
    return this.signerCertificateSchemaValue;
  }

  public override get signerName() {
    return this.signerNameValue;
  }
}

describe('Chain', () => {
  describe('verify', () => {
    describe('Certificate chain', () => {
      test('Signer certificate should be issued by organisation certificate', async () => {
        const otherOrgCertSerialised = await selfIssueOrganisationCertificate(
          ORG_NAME,
          await generateRsaKeyPair(),
          datePeriod.end,
          { startDate: datePeriod.start },
        );
        const chain = new StubChain(
          dnssecChain,
          AsnParser.parse(otherOrgCertSerialised, CertificateSchema),
          MEMBER_CERT_SCHEMA,
        );

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
        const chain = new StubChain(dnssecChain, ORG_CERT_SCHEMA, undefined);

        // This should succeed because the orgCertificate will be used as both
        // the org and signer certificate
        const result = await chain.verify(SERVICE_OID, datePeriod, dnssecChainFixture.trustAnchors);

        expect(result.organisation).toStrictEqual(ORG_NAME);
      });

      test('Certificates should overlap with specified period', async () => {
        const chain = new StubChain(dnssecChain, ORG_CERT_SCHEMA, MEMBER_CERT_SCHEMA);
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
          dnssecChain,
          ORG_CERT_SCHEMA,
          MEMBER_CERT_SCHEMA,
          invalidSignerName,
        );

        await expect(async () =>
          chain.verify(SERVICE_OID, datePeriod, dnssecChainFixture.trustAnchors),
        ).rejects.toThrowWithMessage(VeraidError, errorMessage);
      });

      test('should not contain tabs', async () => {
        const invalidSignerName = `\t${MEMBER_NAME}`;
        const chain = new StubChain(
          dnssecChain,
          ORG_CERT_SCHEMA,
          MEMBER_CERT_SCHEMA,
          invalidSignerName,
        );

        await expect(async () =>
          chain.verify(SERVICE_OID, datePeriod, dnssecChainFixture.trustAnchors),
        ).rejects.toThrowWithMessage(VeraidError, errorMessage);
      });

      test('should not contain carriage returns', async () => {
        const invalidSignerName = `\r${MEMBER_NAME}`;
        const chain = new StubChain(
          dnssecChain,
          ORG_CERT_SCHEMA,
          MEMBER_CERT_SCHEMA,
          invalidSignerName,
        );

        await expect(async () =>
          chain.verify(SERVICE_OID, datePeriod, dnssecChainFixture.trustAnchors),
        ).rejects.toThrowWithMessage(VeraidError, errorMessage);
      });

      test('should not contain line feeds', async () => {
        const invalidSignerName = `\n${MEMBER_NAME}`;
        const chain = new StubChain(
          dnssecChain,
          ORG_CERT_SCHEMA,
          MEMBER_CERT_SCHEMA,
          invalidSignerName,
        );

        await expect(async () =>
          chain.verify(SERVICE_OID, datePeriod, dnssecChainFixture.trustAnchors),
        ).rejects.toThrowWithMessage(VeraidError, errorMessage);
      });
    });

    describe('DNSSEC chain', () => {
      test('Service OID should be verified', async () => {
        const chain = new StubChain(dnssecChain, ORG_CERT_SCHEMA, MEMBER_CERT_SCHEMA);
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
        const chain = new StubChain(dnssecChain, ORG_CERT_SCHEMA, MEMBER_CERT_SCHEMA);
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
        const chain = new StubChain(dnssecChain, ORG_CERT_SCHEMA, MEMBER_CERT_SCHEMA);
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
        const chain = new StubChain(dnssecChain, ORG_CERT_SCHEMA, MEMBER_CERT_SCHEMA);

        // Do not pass trusted anchors
        await expect(async () => chain.verify(SERVICE_OID, datePeriod)).rejects.toThrowWithMessage(
          VeraidError,
          /^VeraId DNSSEC chain is BOGUS/u,
        );
      });
    });

    describe('Valid result', () => {
      test('Organisation name should be output', async () => {
        const chain = new StubChain(dnssecChain, ORG_CERT_SCHEMA, MEMBER_CERT_SCHEMA);

        const { organisation } = await chain.verify(
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
        const chain = new StubChain(
          dnssecChain,
          AsnParser.parse(otherOrgCertificateSerialised, CertificateSchema),
          AsnParser.parse(fixture.memberCertificateSerialised, CertificateSchema),
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
        const chain = new StubChain(dnssecChain, ORG_CERT_SCHEMA, MEMBER_CERT_SCHEMA, MEMBER_NAME);

        const { user } = await chain.verify(
          SERVICE_OID,
          datePeriod,
          dnssecChainFixture.trustAnchors,
        );

        expect(user).toStrictEqual(MEMBER_NAME);
      });

      test('User name should not be output if not provided', async () => {
        const chain = new StubChain(dnssecChain, ORG_CERT_SCHEMA, MEMBER_CERT_SCHEMA);

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
