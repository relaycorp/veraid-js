import { jest } from '@jest/globals';
import {
  DatePeriod,
  Message,
  MockChain,
  Question,
  type Resolver,
  RrSet,
  SecurityStatus,
  type TrustAnchor,
} from '@relaycorp/dnssec';
import { AsnParser } from '@peculiar/asn1-schema';
import { addSeconds, setMilliseconds, subSeconds } from 'date-fns';

import { expectErrorToEqual, getPromiseRejection } from '../../testUtils/errors.js';
import VeraError from '../VeraError.js';
import { ORG_DOMAIN, SERVICE_OID } from '../../testUtils/vera/stubs.js';
import { arrayBufferFrom } from '../../testUtils/buffers.js';
import { serialiseMessage } from '../../testUtils/dns.js';
import {
  ORG_KEY_PAIR,
  ORG_VERA_DOMAIN,
  TTL_OVERRIDE,
  VERA_RDATA_FIELDS,
  VERA_RECORD,
} from '../../testUtils/vera/dns.js';

import { VeraDnssecChain } from './VeraDnssecChain.js';
import { DnssecChainSchema } from './DnssecChainSchema.js';
import { type VeraRdataFields } from './VeraRdataFields.js';
import { generateTxtRdata } from './rdataSerialisation.js';

const mockResolver = jest.fn<Resolver>();
beforeEach(() => {
  mockResolver.mockReset();
});

const VERA_RRSET = RrSet.init(VERA_RECORD.makeQuestion(), [VERA_RECORD]);
const MOCK_CHAIN = await MockChain.generate(ORG_DOMAIN);

describe('VeraDnssecChain', () => {
  describe('retrieve', () => {
    function generateFixture(status: SecurityStatus): readonly TrustAnchor[] {
      const { resolver, trustAnchors } = MOCK_CHAIN.generateFixture(VERA_RRSET, status);
      mockResolver.mockImplementation(resolver);
      return trustAnchors;
    }

    test('TXT subdomain _vera of specified domain should be queried', async () => {
      const trustAnchors = generateFixture(SecurityStatus.SECURE);

      await VeraDnssecChain.retrieve(ORG_DOMAIN, mockResolver, trustAnchors);

      expect(mockResolver).toHaveBeenCalledWith(
        expect.toSatisfy<Question>(
          (question) => question.name === ORG_VERA_DOMAIN && question.getTypeName() === 'TXT',
        ),
      );
    });

    test('Errors should be wrapped', async () => {
      const originalError = new Error('Whoops');
      mockResolver.mockRejectedValue(originalError);

      const error = await getPromiseRejection(
        async () => VeraDnssecChain.retrieve(ORG_DOMAIN, mockResolver, undefined),
        VeraError,
      );

      expect(error.message).toStartWith('Failed to retrieve DNSSEC chain');
      expect(error.cause).toBe(originalError);
    });

    test('Non-SECURE result should be refused', async () => {
      const status = SecurityStatus.BOGUS;
      const trustAnchors = generateFixture(status);

      const error = await getPromiseRejection(
        async () => VeraDnssecChain.retrieve(ORG_DOMAIN, mockResolver, trustAnchors),
        VeraError,
      );

      expect(error.message).toStartWith(`DNSSEC chain validation failed (${status}): `);
    });

    test('Responses in wire format should be supported', async () => {
      const trustAnchors = generateFixture(SecurityStatus.SECURE);
      const resolver: Resolver = async (question) => {
        const response = (await mockResolver(question)) as Message;
        return serialiseMessage(response);
      };

      await expect(VeraDnssecChain.retrieve(ORG_DOMAIN, resolver, trustAnchors)).toResolve();
    });

    test('Domain should be stored in the instance', async () => {
      const trustAnchors = generateFixture(SecurityStatus.SECURE);

      const chain = await VeraDnssecChain.retrieve(ORG_DOMAIN, mockResolver, trustAnchors);

      expect(chain.domainName).toStrictEqual(ORG_DOMAIN);
    });

    test('Responses should be stored in instance', async () => {
      const trustAnchors = generateFixture(SecurityStatus.SECURE);

      const chain = await VeraDnssecChain.retrieve(ORG_DOMAIN, mockResolver, trustAnchors);

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
      const { responses } = MOCK_CHAIN.generateFixture(VERA_RRSET, SecurityStatus.SECURE);
      const responsesSerialised = responses.map(serialiseMessage);
      const chain = new VeraDnssecChain(ORG_DOMAIN, responsesSerialised.map(arrayBufferFrom));

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

    test('Invalid chain should be refused', async () => {
      const status = SecurityStatus.INSECURE;
      const { responses, trustAnchors } = MOCK_CHAIN.generateFixture(
        VERA_RRSET,
        status,
        datePeriod,
      );
      const responsesSerialised = responses.map(serialiseMessage).map(arrayBufferFrom);
      const chain = new VeraDnssecChain(ORG_DOMAIN, responsesSerialised);

      await expect(async () => chain.verify(datePeriod, trustAnchors)).rejects.toThrowWithMessage(
        VeraError,
        // eslint-disable-next-line security/detect-non-literal-regexp,require-unicode-regexp
        new RegExp(`^Vera DNSSEC chain is invalid (${status}): `),
      );
    });

    test('DNSSEC lookup errors should be wrapped', async () => {
      const { trustAnchors } = MOCK_CHAIN.generateFixture(
        VERA_RRSET,
        SecurityStatus.SECURE,
        datePeriod,
      );
      const invalidResponse = new Message({ rcode: 0 }, [new Question('.', 'DNSKEY', 'IN')], []);
      const chain = new VeraDnssecChain(ORG_DOMAIN, [arrayBufferFrom(invalidResponse.serialise())]);

      const error = await getPromiseRejection(
        async () => chain.verify(datePeriod, trustAnchors),
        VeraError,
      );

      expectErrorToEqual(
        error,
        new VeraError('Failed to process DNSSEC verification offline', {
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
        VERA_RRSET,
        SecurityStatus.SECURE,
        pastPeriod,
      );
      const responsesSerialised = responses.map(serialiseMessage).map(arrayBufferFrom);
      const chain = new VeraDnssecChain(ORG_DOMAIN, responsesSerialised);

      await expect(async () => chain.verify(datePeriod, trustAnchors)).rejects.toThrowWithMessage(
        VeraError,
        /^Vera DNSSEC chain is invalid /u,
      );
    });

    test('Chain valid in the future should be refused', async () => {
      const futurePeriod = DatePeriod.init(
        addSeconds(datePeriod.end, 1),
        addSeconds(datePeriod.end, 2),
      );
      const { responses, trustAnchors } = MOCK_CHAIN.generateFixture(
        VERA_RRSET,
        SecurityStatus.SECURE,
        futurePeriod,
      );
      const responsesSerialised = responses.map(serialiseMessage).map(arrayBufferFrom);
      const chain = new VeraDnssecChain(ORG_DOMAIN, responsesSerialised);

      await expect(async () => chain.verify(datePeriod, trustAnchors)).rejects.toThrowWithMessage(
        VeraError,
        /^Vera DNSSEC chain is invalid /u,
      );
    });

    test('RData should be output if chain is valid', async () => {
      const { responses, trustAnchors } = MOCK_CHAIN.generateFixture(
        VERA_RRSET,
        SecurityStatus.SECURE,
        datePeriod,
      );
      const responsesSerialised = responses.map(serialiseMessage).map(arrayBufferFrom);
      const chain = new VeraDnssecChain(ORG_DOMAIN, responsesSerialised);

      const rdataFieldSet = await chain.verify(datePeriod, trustAnchors);

      expect(rdataFieldSet).toHaveLength(1);
      const [rdataFields] = rdataFieldSet;
      expect(rdataFields).toStrictEqual<VeraRdataFields>(VERA_RDATA_FIELDS);
    });

    test('Multiple RData should be output if there were multiple TXT records', async () => {
      const additionalVeraRdata = await generateTxtRdata(
        ORG_KEY_PAIR.publicKey,
        TTL_OVERRIDE,
        SERVICE_OID,
      );
      const additionalVeraRecord = VERA_RECORD.shallowCopy({ data: additionalVeraRdata });
      const rrset = RrSet.init(VERA_RECORD.makeQuestion(), [VERA_RECORD, additionalVeraRecord]);
      const { responses, trustAnchors } = MOCK_CHAIN.generateFixture(
        rrset,
        SecurityStatus.SECURE,
        datePeriod,
      );
      const responsesSerialised = responses.map(serialiseMessage).map(arrayBufferFrom);
      const chain = new VeraDnssecChain(ORG_DOMAIN, responsesSerialised);

      const rdataFieldSet = await chain.verify(datePeriod, trustAnchors);

      expect(rdataFieldSet).toHaveLength(2);
      const [rdata1Fields, rdata2Fields] = rdataFieldSet;
      expect(rdata1Fields).toStrictEqual<VeraRdataFields>(VERA_RDATA_FIELDS);
      expect(rdata2Fields).toStrictEqual<VeraRdataFields>({
        ...VERA_RDATA_FIELDS,
        serviceOid: SERVICE_OID,
      });
    });
  });
});
