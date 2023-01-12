import { jest } from '@jest/globals';
import { DnsRecord, Message } from '@relaycorp/dnssec';
import { DNSoverHTTPS } from 'dohdec';

import { arrayBufferFrom } from '../../testUtils/buffers.js';
import VeraError from '../VeraError.js';
import { ORG_NAME } from '../../testUtils/veraStubs.js';

import { dnssecOnlineResolve, makeDnssecOfflineResolver } from './dnssec.js';

const STUB_RECORD = new DnsRecord(ORG_NAME, 'TXT', 'IN', 42, 'foo');
const STUB_QUESTION = STUB_RECORD.makeQuestion();
const STUB_RESPONSE = new Message({ rcode: 0 }, [STUB_QUESTION], [STUB_RECORD]);
const STUB_DNS_RESPONSE_SERIALISED = STUB_RESPONSE.serialise();

describe('dnssecOnlineResolve', () => {
  const mockDohLookup = jest.spyOn(DNSoverHTTPS.prototype, 'lookup');
  beforeEach(() => {
    mockDohLookup.mockReset().mockResolvedValue(STUB_DNS_RESPONSE_SERIALISED);
  });

  test('Specified question should be queried', async () => {
    await dnssecOnlineResolve(STUB_QUESTION);

    expect(mockDohLookup).toHaveBeenCalledWith(
      STUB_QUESTION.name,
      expect.objectContaining({
        rrtype: STUB_QUESTION.getTypeName(),
      }),
    );
  });

  test('DNS message should be requested in wire format', async () => {
    await dnssecOnlineResolve(STUB_QUESTION);

    expect(mockDohLookup).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ json: false }),
    );
  });

  test('DNS message should not be parsed by DoH library', async () => {
    await dnssecOnlineResolve(STUB_QUESTION);

    expect(mockDohLookup).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ decode: false }),
    );
  });

  test('RRSIG records should be retrieved', async () => {
    await dnssecOnlineResolve(STUB_QUESTION);

    expect(mockDohLookup).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ dnssec: true }),
    );
  });

  test('Server-side DNSSEC validation should be disabled', async () => {
    await dnssecOnlineResolve(STUB_QUESTION);

    expect(mockDohLookup).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ dnssecCheckingDisabled: true }),
    );
  });

  test('Response should be returned', async () => {
    const response = await dnssecOnlineResolve(STUB_QUESTION);

    expect(response).toBe(STUB_DNS_RESPONSE_SERIALISED);
  });
});

describe('makeDnssecOfflineResolver', () => {
  test('Malformed responses should be refused', () => {
    const malformedResponse = arrayBufferFrom('malformed');

    expect(() => makeDnssecOfflineResolver([malformedResponse])).toThrowWithMessage(
      VeraError,
      'At least one of the response messages is malformed',
    );
  });

  describe('Resolver', () => {
    test('Existing response should be returned', async () => {
      const resolver = makeDnssecOfflineResolver([arrayBufferFrom(STUB_DNS_RESPONSE_SERIALISED)]);

      const response = (await resolver(STUB_QUESTION)) as Message;
      expect(Buffer.from(response.serialise())).toStrictEqual(
        Buffer.from(STUB_DNS_RESPONSE_SERIALISED),
      );
    });

    test('Missing response should result in error', async () => {
      const resolver = makeDnssecOfflineResolver([]);

      await expect(resolver(STUB_QUESTION)).rejects.toThrowWithMessage(
        VeraError,
        `Could not find response for ${STUB_QUESTION.key}`,
      );
    });
  });
});
