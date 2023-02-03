import { jest } from '@jest/globals';
import { DnsRecord, Message } from '@relaycorp/dnssec';
import { DNSoverHTTPS } from 'dohdec';

import { serialiseMessage } from '../../testUtils/dns.js';
import { ORG_NAME } from '../../testUtils/veraStubs/organisation.js';

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
  test('Existing response should be returned', async () => {
    const resolver = makeDnssecOfflineResolver([STUB_RESPONSE]);

    const response = (await resolver(STUB_QUESTION)) as Message;
    expect(serialiseMessage(response)).toStrictEqual(Buffer.from(STUB_DNS_RESPONSE_SERIALISED));
  });

  test('Missing response should result in NXDOMAIN response', async () => {
    const resolver = makeDnssecOfflineResolver([]);

    const response = (await resolver(STUB_QUESTION)) as Message;

    expect(response.header.rcode).toBe(3);
    expect(response.questions).toHaveLength(1);
    expect(response.questions[0].equals(STUB_QUESTION)).toBeTrue();
    expect(response.answers).toBeEmpty();
  });
});
