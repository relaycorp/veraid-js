import { jest } from '@jest/globals';
import { AsnParser } from '@peculiar/asn1-schema';
import {
  DnsClass,
  DnsRecord,
  type Message,
  MockChain,
  type Question,
  type Resolver,
  RrSet,
  SecurityStatus,
  type TrustAnchor,
} from '@relaycorp/dnssec';

import { getPromiseRejection } from '../../testUtils/errors.js';
import VeraError from '../VeraError.js';

import { retrieveDnssecChain } from './dnssecChainRetrieval.js';
import { DnssecChain } from './DnssecChain.js';

const mockResolver = jest.fn<Resolver>();
beforeEach(() => {
  mockResolver.mockReset();
});

const STUB_DOMAIN = 'example.com.';

const STUB_RECORD = new DnsRecord(
  `_vera.${STUB_DOMAIN}`,
  'TXT',
  DnsClass.IN,
  42,
  'foo' as unknown as object,
);
const RRSET = RrSet.init(STUB_RECORD.makeQuestion(), [STUB_RECORD]);

let mockChain: MockChain;
beforeAll(async () => {
  mockChain = await MockChain.generate(STUB_DOMAIN);
});

describe('retrieveDnssecChain', () => {
  function generateFixture(status: SecurityStatus): readonly TrustAnchor[] {
    const { resolver, trustAnchors } = mockChain.generateFixture(RRSET, status);
    mockResolver.mockImplementation(resolver);
    return trustAnchors;
  }

  test('TXT subdomain _vera of specified domain should be queried', async () => {
    const trustAnchors = generateFixture(SecurityStatus.SECURE);

    await retrieveDnssecChain(STUB_DOMAIN, mockResolver, trustAnchors);

    expect(mockResolver).toHaveBeenCalledWith(
      expect.toSatisfy<Question>(
        (question) => question.name === `_vera.${STUB_DOMAIN}` && question.getTypeName() === 'TXT',
      ),
    );
  });

  test('DoH resolver should be used by default', async () => {
    const trustAnchors = generateFixture(SecurityStatus.SECURE);

    await retrieveDnssecChain(STUB_DOMAIN, mockResolver, trustAnchors);

    expect(mockResolver).toHaveBeenCalledWith(
      expect.toSatisfy<Question>(
        (question) => question.name === `_vera.${STUB_DOMAIN}` && question.getTypeName() === 'TXT',
      ),
    );
  });

  test('Errors should be wrapped', async () => {
    const originalError = new Error('Whoops');
    mockResolver.mockRejectedValue(originalError);

    const error = await getPromiseRejection(
      async () => retrieveDnssecChain(STUB_DOMAIN, mockResolver, undefined),
      VeraError,
    );

    expect(error.message).toStartWith('Failed to retrieve DNSSEC chain');
    expect(error.cause).toBe(originalError);
  });

  test('Non-SECURE result should be refused', async () => {
    const status = SecurityStatus.BOGUS;
    const trustAnchors = generateFixture(status);

    const error = await getPromiseRejection(
      async () => retrieveDnssecChain(STUB_DOMAIN, mockResolver, trustAnchors),
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

    await expect(retrieveDnssecChain(STUB_DOMAIN, resolver, trustAnchors)).toResolve();
  });

  test('Responses should be wrapped in an explicitly tagged SET', async () => {
    const trustAnchors = generateFixture(SecurityStatus.SECURE);

    const chainSerialised = await retrieveDnssecChain(STUB_DOMAIN, mockResolver, trustAnchors);

    const chain = AsnParser.parse(chainSerialised, DnssecChain);
    expect(chain).toHaveLength(mockResolver.mock.calls.length);
    expect(chain.length).toBeGreaterThan(0);
    const responses = await Promise.all(
      mockResolver.mock.results.map((promise) => promise.value as Message),
    );
    const responsesSerialised = responses.map((response) => Buffer.from(response.serialise()));
    chain.forEach((response) => {
      expect(responsesSerialised).toContainEqual(Buffer.from(response));
    });
  });
});
