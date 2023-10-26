import { jest } from '@jest/globals';
import {
  Message,
  Question,
  type Resolver,
  RrSet,
  SecurityStatus,
  type TrustAnchor,
} from '@relaycorp/dnssec';
import { AsnParser } from '@peculiar/asn1-schema';
import { addSeconds, setMilliseconds, subSeconds } from 'date-fns';

import { expectErrorToEqual, getPromiseRejection } from '../../testUtils/errors.js';
import VeraidError from '../VeraidError.js';
import { arrayBufferFrom } from '../../testUtils/buffers.js';
import { serialiseMessage } from '../../testUtils/dns.js';
import {
  ORG_DOMAIN,
  ORG_KEY_PAIR,
  ORG_KEY_SPEC,
  ORG_VERAID_DOMAIN,
  VERAID_RECORD,
  VERAID_RECORD_TTL_OVERRIDE,
} from '../../testUtils/veraStubs/organisation.js';
import { SERVICE_OID } from '../../testUtils/veraStubs/service.js';
import { MOCK_CHAIN, VERAID_RRSET } from '../../testUtils/veraStubs/dnssec.js';
import { DatePeriod } from '../dates.js';
import { DnssecChainSchema } from '../schemas/DnssecChainSchema.js';

import { VeraidDnssecChain } from './VeraidDnssecChain.js';
import { generateTxtRdata } from './rdataSerialisation.js';

const mockResolver = jest.fn<Resolver>();
beforeEach(() => {
  mockResolver.mockReset();
});

describe('VeraDnssecChain', () => {
  describe('retrieve', () => {
    function generateFixture(status: SecurityStatus): readonly TrustAnchor[] {
      const { resolver, trustAnchors } = MOCK_CHAIN.generateFixture(VERAID_RRSET, status);
      mockResolver.mockImplementation(resolver);
      return trustAnchors;
    }

    test('TXT subdomain _veraid of specified domain should be queried', async () => {
      const trustAnchors = generateFixture(SecurityStatus.SECURE);

      await VeraidDnssecChain.retrieve(ORG_DOMAIN, mockResolver, trustAnchors);

      expect(mockResolver).toHaveBeenCalledWith(
        expect.toSatisfy<Question>(
          (question) => question.name === ORG_VERAID_DOMAIN && question.getTypeName() === 'TXT',
        ),
      );
    });

    test('Errors should be wrapped', async () => {
      const originalError = new Error('Whoops');
      mockResolver.mockRejectedValue(originalError);

      const error = await getPromiseRejection(
        async () => VeraidDnssecChain.retrieve(ORG_DOMAIN, mockResolver, undefined),
        VeraidError,
      );

      expect(error.message).toStartWith('Failed to retrieve DNSSEC chain');
      expect(error.cause).toBe(originalError);
    });

    test('Non-SECURE result should be refused', async () => {
      const status = SecurityStatus.BOGUS;
      const trustAnchors = generateFixture(status);

      const error = await getPromiseRejection(
        async () => VeraidDnssecChain.retrieve(ORG_DOMAIN, mockResolver, trustAnchors),
        VeraidError,
      );

      expect(error.message).toStartWith(`DNSSEC chain validation failed (${status}): `);
    });

    test('Responses in wire format should be supported', async () => {
      const trustAnchors = generateFixture(SecurityStatus.SECURE);
      const resolver: Resolver = async (question) => {
        const response = (await mockResolver(question)) as Message;
        return serialiseMessage(response);
      };

      await expect(VeraidDnssecChain.retrieve(ORG_DOMAIN, resolver, trustAnchors)).toResolve();
    });

    test('Domain should be stored in the instance', async () => {
      const trustAnchors = generateFixture(SecurityStatus.SECURE);

      const chain = await VeraidDnssecChain.retrieve(ORG_DOMAIN, mockResolver, trustAnchors);

      expect(chain.domainName).toStrictEqual(ORG_DOMAIN);
    });

    test('Responses should be stored in instance', async () => {
      const trustAnchors = generateFixture(SecurityStatus.SECURE);

      const chain = await VeraidDnssecChain.retrieve(ORG_DOMAIN, mockResolver, trustAnchors);

      expect(chain.responses).toHaveLength(mockResolver.mock.calls.length);
      expect(chain.responses.length).toBeGreaterThan(0);
      const responses = await Promise.all(
        mockResolver.mock.results.map((promise) => promise.value as Message),
      );
      const responsesSerialised = responses.map(serialiseMessage);
      chain.responses.forEach((response) => {
        expect(responsesSerialised).toContainEqual(Buffer.from(response));
      });
    });
  });

  describe('serialise', () => {
    test('Responses should be wrapped in an explicitly tagged SET', () => {
      const { responses } = MOCK_CHAIN.generateFixture(VERAID_RRSET, SecurityStatus.SECURE);
      const responsesSerialised = responses.map(serialiseMessage);
      const chain = new VeraidDnssecChain(ORG_DOMAIN, responsesSerialised.map(arrayBufferFrom));

      const chainSerialised = chain.serialise();

      const chainDeserialised = AsnParser.parse(chainSerialised, DnssecChainSchema);
      chainDeserialised.forEach((response) => {
        expect(responsesSerialised).toContainEqual(Buffer.from(response));
      });
    });
  });

  describe('verify', () => {
    const now = setMilliseconds(new Date(), 0);
    const datePeriod = DatePeriod.init(subSeconds(now, 60), now);

    test('Malformed responses should be refused', async () => {
      const malformedResponse = arrayBufferFrom('malformed');
      const chain = new VeraidDnssecChain(ORG_DOMAIN, [malformedResponse]);

      await expect(async () =>
        chain.verify(ORG_KEY_SPEC, SERVICE_OID, datePeriod),
      ).rejects.toThrowWithMessage(
        VeraidError,
        'At least one of the response messages is malformed',
      );
    });

    test('Chain with missing VeraId TXT should be refused', async () => {
      const { responses } = MOCK_CHAIN.generateFixture(
        VERAID_RRSET,
        SecurityStatus.SECURE,
        datePeriod,
      );
      const incompleteResponses = responses.filter(
        (response) => !response.answersQuestion(VERAID_RECORD.makeQuestion()),
      );
      const responsesSerialised = incompleteResponses.map(serialiseMessage).map(arrayBufferFrom);
      const chain = new VeraidDnssecChain(ORG_DOMAIN, responsesSerialised);

      await expect(async () =>
        chain.verify(ORG_KEY_SPEC, SERVICE_OID, datePeriod),
      ).rejects.toThrowWithMessage(VeraidError, 'Chain is missing VeraId TXT response');
    });

    test('Chain with multiple VeraId TXT responses should be refused', async () => {
      const { responses } = MOCK_CHAIN.generateFixture(
        VERAID_RRSET,
        SecurityStatus.SECURE,
        datePeriod,
      );
      const veraTxtResponse = responses.find((response) =>
        response.answersQuestion(VERAID_RECORD.makeQuestion()),
      )!;
      const responsesSerialised = [...responses, veraTxtResponse]
        .map(serialiseMessage)
        .map(arrayBufferFrom);
      const chain = new VeraidDnssecChain(ORG_DOMAIN, responsesSerialised);

      await expect(async () =>
        chain.verify(ORG_KEY_SPEC, SERVICE_OID, datePeriod),
      ).rejects.toThrowWithMessage(VeraidError, 'Chain contains multiple VeraId TXT responses');
    });

    describe('Rdata', () => {
      test('Algorithm id should match that of specified key spec', async () => {
        const { responses, trustAnchors } = MOCK_CHAIN.generateFixture(
          VERAID_RRSET,
          SecurityStatus.SECURE,
          datePeriod,
        );
        const responsesSerialised = responses.map(serialiseMessage).map(arrayBufferFrom);
        const chain = new VeraidDnssecChain(ORG_DOMAIN, responsesSerialised);
        const spec = { ...ORG_KEY_SPEC, keyAlgorithm: ORG_KEY_SPEC.keyAlgorithm + 1 };

        await expect(async () =>
          chain.verify(spec, SERVICE_OID, datePeriod, trustAnchors),
        ).rejects.toThrowWithMessage(
          VeraidError,
          'Could not find VeraId record for specified key and/or service',
        );
      });

      test('Key id should match that of specified key spec', async () => {
        const { responses, trustAnchors } = MOCK_CHAIN.generateFixture(
          VERAID_RRSET,
          SecurityStatus.SECURE,
          datePeriod,
        );
        const responsesSerialised = responses.map(serialiseMessage).map(arrayBufferFrom);
        const chain = new VeraidDnssecChain(ORG_DOMAIN, responsesSerialised);
        const spec = { ...ORG_KEY_SPEC, keyId: `not-${ORG_KEY_SPEC.keyId}` };

        await expect(async () =>
          chain.verify(spec, SERVICE_OID, datePeriod, trustAnchors),
        ).rejects.toThrowWithMessage(
          VeraidError,
          'Could not find VeraId record for specified key and/or service',
        );
      });

      test('Absence of service OID should allow any service', async () => {
        const record = VERAID_RECORD.shallowCopy({
          data: await generateTxtRdata(ORG_KEY_PAIR.publicKey, VERAID_RECORD_TTL_OVERRIDE),
        });
        const { responses, trustAnchors } = MOCK_CHAIN.generateFixture(
          RrSet.init(record.makeQuestion(), [record]),
          SecurityStatus.SECURE,
          datePeriod,
        );
        const responsesSerialised = responses.map(serialiseMessage).map(arrayBufferFrom);
        const chain = new VeraidDnssecChain(ORG_DOMAIN, responsesSerialised);

        await expect(chain.verify(ORG_KEY_SPEC, SERVICE_OID, datePeriod, trustAnchors)).toResolve();
      });

      test('Presence of service OID should only allow matching service', async () => {
        const record = VERAID_RECORD.shallowCopy({
          data: await generateTxtRdata(
            ORG_KEY_PAIR.publicKey,
            VERAID_RECORD_TTL_OVERRIDE,
            SERVICE_OID,
          ),
        });
        const { responses, trustAnchors } = MOCK_CHAIN.generateFixture(
          RrSet.init(record.makeQuestion(), [record]),
          SecurityStatus.SECURE,
          datePeriod,
        );
        const responsesSerialised = responses.map(serialiseMessage).map(arrayBufferFrom);
        const chain = new VeraidDnssecChain(ORG_DOMAIN, responsesSerialised);

        await expect(chain.verify(ORG_KEY_SPEC, SERVICE_OID, datePeriod, trustAnchors)).toResolve();
      });

      test('Presence of service OID should only deny mismatching service', async () => {
        const record = VERAID_RECORD.shallowCopy({
          data: await generateTxtRdata(
            ORG_KEY_PAIR.publicKey,
            VERAID_RECORD_TTL_OVERRIDE,
            `1.${SERVICE_OID}`,
          ),
        });
        const { responses, trustAnchors } = MOCK_CHAIN.generateFixture(
          RrSet.init(record.makeQuestion(), [record]),
          SecurityStatus.SECURE,
          datePeriod,
        );
        const responsesSerialised = responses.map(serialiseMessage).map(arrayBufferFrom);
        const chain = new VeraidDnssecChain(ORG_DOMAIN, responsesSerialised);

        await expect(async () =>
          chain.verify(ORG_KEY_SPEC, SERVICE_OID, datePeriod, trustAnchors),
        ).rejects.toThrowWithMessage(
          VeraidError,
          'Could not find VeraId record for specified key and/or service',
        );
      });

      test('Explicit service OID should take precedence over wildcard', async () => {
        const genericRecord = VERAID_RECORD.shallowCopy({
          data: await generateTxtRdata(ORG_KEY_PAIR.publicKey, VERAID_RECORD_TTL_OVERRIDE),
        });
        const concreteRecordTtl = 1;
        const concreteRecord = VERAID_RECORD.shallowCopy({
          data: await generateTxtRdata(ORG_KEY_PAIR.publicKey, concreteRecordTtl, SERVICE_OID),
        });
        const { responses, trustAnchors } = MOCK_CHAIN.generateFixture(
          RrSet.init(concreteRecord.makeQuestion(), [genericRecord, concreteRecord]),
          SecurityStatus.SECURE,
          DatePeriod.init(datePeriod.start, subSeconds(datePeriod.end, concreteRecordTtl + 1)),
        );
        const responsesSerialised = responses.map(serialiseMessage).map(arrayBufferFrom);
        const chain = new VeraidDnssecChain(ORG_DOMAIN, responsesSerialised);

        // It should fail because the concrete record should've already expired.
        await expect(chain.verify(ORG_KEY_SPEC, SERVICE_OID, datePeriod, trustAnchors)).toReject();
      });

      test('TTL override should truncate validity period of chain', async () => {
        const ttlOverrideSeconds = 1;
        const record = VERAID_RECORD.shallowCopy({
          data: await generateTxtRdata(ORG_KEY_PAIR.publicKey, ttlOverrideSeconds),
        });
        const chainPeriod = DatePeriod.init(
          datePeriod.start,
          subSeconds(datePeriod.end, ttlOverrideSeconds + 1),
        );
        const { responses, trustAnchors } = MOCK_CHAIN.generateFixture(
          RrSet.init(record.makeQuestion(), [record]),
          SecurityStatus.SECURE,
          chainPeriod,
        );
        const responsesSerialised = responses.map(serialiseMessage).map(arrayBufferFrom);
        const chain = new VeraidDnssecChain(ORG_DOMAIN, responsesSerialised);

        await expect(async () =>
          chain.verify(ORG_KEY_SPEC, SERVICE_OID, datePeriod, trustAnchors),
        ).rejects.toThrowWithMessage(VeraidError, /^VeraId DNSSEC chain is BOGUS: /u);
      });
    });

    describe('DNSSEC', () => {
      test('Invalid chain should be refused', async () => {
        const status = SecurityStatus.INSECURE;
        const { responses, trustAnchors } = MOCK_CHAIN.generateFixture(
          VERAID_RRSET,
          status,
          datePeriod,
        );
        const responsesSerialised = responses.map(serialiseMessage).map(arrayBufferFrom);
        const chain = new VeraidDnssecChain(ORG_DOMAIN, responsesSerialised);

        await expect(async () =>
          chain.verify(ORG_KEY_SPEC, SERVICE_OID, datePeriod, trustAnchors),
        ).rejects.toThrowWithMessage(
          VeraidError,
          // eslint-disable-next-line security/detect-non-literal-regexp,require-unicode-regexp
          new RegExp(`^VeraId DNSSEC chain is ${status}: `),
        );
      });

      test('Lookup errors should be wrapped', async () => {
        const { responses, trustAnchors } = MOCK_CHAIN.generateFixture(
          VERAID_RRSET,
          SecurityStatus.SECURE,
          datePeriod,
        );
        const invalidResponse = new Message({ rcode: 0 }, [new Question('.', 'DNSKEY', 'IN')], []);
        const veraTxtResponse = responses.find((response) =>
          response.answersQuestion(VERAID_RECORD.makeQuestion()),
        )!;
        const finalResponses = [veraTxtResponse, invalidResponse]
          .map((response) => response.serialise())
          .map(arrayBufferFrom);
        const chain = new VeraidDnssecChain(ORG_DOMAIN, finalResponses);

        const error = await getPromiseRejection(
          async () => chain.verify(ORG_KEY_SPEC, SERVICE_OID, datePeriod, trustAnchors),
          VeraidError,
        );

        expectErrorToEqual(
          error,
          new VeraidError('Failed to process DNSSEC verification offline', {
            cause: expect.any(Error),
          }),
        );
      });

      test('Expired chain should be refused', async () => {
        const pastPeriod = DatePeriod.init(
          subSeconds(datePeriod.start, 2),
          subSeconds(datePeriod.start, 1),
        );
        const { responses, trustAnchors } = MOCK_CHAIN.generateFixture(
          VERAID_RRSET,
          SecurityStatus.SECURE,
          pastPeriod,
        );
        const responsesSerialised = responses.map(serialiseMessage).map(arrayBufferFrom);
        const chain = new VeraidDnssecChain(ORG_DOMAIN, responsesSerialised);

        await expect(async () =>
          chain.verify(ORG_KEY_SPEC, SERVICE_OID, datePeriod, trustAnchors),
        ).rejects.toThrowWithMessage(VeraidError, /^VeraId DNSSEC chain is BOGUS: /u);
      });

      test('Chain valid in the future should be refused', async () => {
        const futurePeriod = DatePeriod.init(
          addSeconds(datePeriod.end, 1),
          addSeconds(datePeriod.end, 2),
        );
        const { responses, trustAnchors } = MOCK_CHAIN.generateFixture(
          VERAID_RRSET,
          SecurityStatus.SECURE,
          futurePeriod,
        );
        const responsesSerialised = responses.map(serialiseMessage).map(arrayBufferFrom);
        const chain = new VeraidDnssecChain(ORG_DOMAIN, responsesSerialised);

        await expect(async () =>
          chain.verify(ORG_KEY_SPEC, SERVICE_OID, datePeriod, trustAnchors),
        ).rejects.toThrowWithMessage(VeraidError, /^VeraId DNSSEC chain is BOGUS: /u);
      });

      test('Valid chain should verify successfully', async () => {
        const { responses, trustAnchors } = MOCK_CHAIN.generateFixture(
          VERAID_RRSET,
          SecurityStatus.SECURE,
          datePeriod,
        );
        const responsesSerialised = responses.map(serialiseMessage).map(arrayBufferFrom);
        const chain = new VeraidDnssecChain(ORG_DOMAIN, responsesSerialised);

        await expect(chain.verify(ORG_KEY_SPEC, SERVICE_OID, datePeriod, trustAnchors)).toResolve();
      });
    });
  });
});
