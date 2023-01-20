import { jest } from '@jest/globals';
import {
  type Message,
  MockChain,
  type Question,
  type Resolver,
  RrSet,
  SecurityStatus,
  type TrustAnchor,
} from '@relaycorp/dnssec';
import { AsnParser } from '@peculiar/asn1-schema';

import { getPromiseRejection } from '../../testUtils/errors.js';
import VeraError from '../VeraError.js';
import { ORG_DOMAIN, ORG_VERA_DOMAIN, VERA_RECORD } from '../../testUtils/veraStubs.js';
import { arrayBufferFrom } from '../../testUtils/buffers.js';

import { VeraDnssecChain } from './VeraDnssecChain.js';
import { DnssecChainSchema } from './DnssecChainSchema.js';

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
        return Buffer.from(response.serialise());
      };

      await expect(VeraDnssecChain.retrieve(ORG_DOMAIN, resolver, trustAnchors)).toResolve();
    });

    test('Responses should be stored in instance', async () => {
      const trustAnchors = generateFixture(SecurityStatus.SECURE);

      const chain = await VeraDnssecChain.retrieve(ORG_DOMAIN, mockResolver, trustAnchors);

      expect(chain.responses).toHaveLength(mockResolver.mock.calls.length);
      expect(chain.responses.length).toBeGreaterThan(0);
      const responses = await Promise.all(
        mockResolver.mock.results.map((promise) => promise.value as Message),
      );
      const responsesSerialised = responses.map((response) => Buffer.from(response.serialise()));
      chain.responses.forEach((response) => {
        expect(responsesSerialised).toContainEqual(Buffer.from(response));
      });
    });
  });

  describe('serialise', () => {
    test('Responses should be wrapped in an explicitly tagged SET', () => {
      const { responses } = MOCK_CHAIN.generateFixture(VERA_RRSET, SecurityStatus.SECURE);
      const responsesSerialised = responses.map((response) => Buffer.from(response.serialise()));
      const chain = new VeraDnssecChain(responsesSerialised.map(arrayBufferFrom));

      const chainSerialised = chain.serialise();

      const chainDeserialised = AsnParser.parse(chainSerialised, DnssecChainSchema);
      chainDeserialised.forEach((response) => {
        expect(responsesSerialised).toContainEqual(Buffer.from(response));
      });
    });
  });
});
