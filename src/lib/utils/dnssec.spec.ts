import { beforeEach, jest } from '@jest/globals';
import { Question } from '@relaycorp/dnssec';
import { DNSoverHTTPS } from 'dohdec';

import { dnssecResolve } from './dnssec.js';

const STUB_QUESTION = new Question('example.com', 'A');
const STUB_DNS_RESPONSE = Buffer.from('The DNS response');

describe('dnssecResolve', () => {
  const mockDohLookup = jest.spyOn(DNSoverHTTPS.prototype, 'lookup');
  beforeEach(() => {
    mockDohLookup.mockReset().mockResolvedValue(STUB_DNS_RESPONSE);
  });

  test('Specified question should be queried', async () => {
    await dnssecResolve(STUB_QUESTION);

    expect(mockDohLookup).toHaveBeenCalledWith(
      STUB_QUESTION.name,
      expect.objectContaining({
        rrtype: STUB_QUESTION.getTypeName(),
      }),
    );
  });

  test('DNS message should be requested in wire format', async () => {
    await dnssecResolve(STUB_QUESTION);

    expect(mockDohLookup).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ json: false }),
    );
  });

  test('DNS message should not be parsed by DoH library', async () => {
    await dnssecResolve(STUB_QUESTION);

    expect(mockDohLookup).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ decode: false }),
    );
  });

  test('RRSIG records should be retrieved', async () => {
    await dnssecResolve(STUB_QUESTION);

    expect(mockDohLookup).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ dnssec: true }),
    );
  });

  test('Server-side DNSSEC validation should be disabled', async () => {
    await dnssecResolve(STUB_QUESTION);

    expect(mockDohLookup).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ dnssecCheckingDisabled: true }),
    );
  });

  test('Response should be returned', async () => {
    const response = await dnssecResolve(STUB_QUESTION);

    expect(response).toBe(STUB_DNS_RESPONSE);
  });
});
