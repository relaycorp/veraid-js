import { DnsRecord, Message } from '@relaycorp/dnssec';

import { serialiseMessage } from '../../testUtils/dns.js';
import { ORG_NAME } from '../../testUtils/veraStubs/organisation.js';

import { makeDnssecOfflineResolver } from './offlineDnsResolver.js';

const STUB_RECORD = new DnsRecord(ORG_NAME, 'TXT', 'IN', 42, 'foo');
const STUB_QUESTION = STUB_RECORD.makeQuestion();
const STUB_RESPONSE = new Message({ rcode: 0 }, [STUB_QUESTION], [STUB_RECORD]);
const STUB_DNS_RESPONSE_SERIALISED = STUB_RESPONSE.serialise();

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
