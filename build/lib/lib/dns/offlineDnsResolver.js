import { Message } from '@relaycorp/dnssec';
const NXDOMAIN_RCODE = 3;
export function makeDnssecOfflineResolver(responses) {
    // eslint-disable-next-line @typescript-eslint/require-await
    return async (question) => {
        const matchingResponse = responses.find((response) => response.answersQuestion(question));
        if (!matchingResponse) {
            return new Message({ rcode: NXDOMAIN_RCODE }, [question], []);
        }
        return matchingResponse;
    };
}
//# sourceMappingURL=offlineDnsResolver.js.map