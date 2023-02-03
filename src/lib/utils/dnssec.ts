import { Message, type Question, type Resolver } from '@relaycorp/dnssec';
import { DNSoverHTTPS } from 'dohdec';

const NXDOMAIN_RCODE = 3;

const DOH = new DNSoverHTTPS({ url: 'https://cloudflare-dns.com/dns-query' });

export async function dnssecOnlineResolve(question: Question): Promise<Buffer> {
  const response = await DOH.lookup(question.name, {
    decode: false,
    dnssec: true,
    dnssecCheckingDisabled: true,
    json: false,
    rrtype: question.getTypeName(),
  });
  return response as Buffer;
}

export function makeDnssecOfflineResolver(responses: readonly Message[]): Resolver {
  // eslint-disable-next-line @typescript-eslint/require-await
  return async (question) => {
    const matchingResponse = responses.find((response) => response.answersQuestion(question));
    if (!matchingResponse) {
      return new Message({ rcode: NXDOMAIN_RCODE }, [question], []);
    }
    return matchingResponse;
  };
}
