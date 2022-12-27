import { type Question } from '@relaycorp/dnssec';
import { DNSoverHTTPS } from 'dohdec';

const DOH = new DNSoverHTTPS({ url: 'https://cloudflare-dns.com/dns-query' });

export async function dnssecResolve(question: Question): Promise<Buffer> {
  const response = await DOH.lookup(question.name, {
    decode: false,
    dnssec: true,
    dnssecCheckingDisabled: true,
    json: false,
    rrtype: question.getTypeName(),
  });
  return response as Buffer;
}
