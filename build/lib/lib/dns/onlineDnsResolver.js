import { DNSoverHTTPS } from 'dohdec';
const DOH = new DNSoverHTTPS({ url: 'https://cloudflare-dns.com/dns-query' });
export async function dnssecOnlineResolve(question) {
    const response = await DOH.lookup(question.name, {
        decode: false,
        dnssec: true,
        dnssecCheckingDisabled: true,
        json: false,
        rrtype: question.getTypeName(),
    });
    return response;
}
//# sourceMappingURL=onlineDnsResolver.js.map