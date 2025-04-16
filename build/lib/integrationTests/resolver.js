import { dnssecOnlineResolve } from '../lib/dns/onlineDnsResolver.js';
const RETRY_ATTEMPTS = 3;
async function retryUponFailure(wrappedFunction, attempts) {
    try {
        return await wrappedFunction();
    }
    catch (error) {
        if (attempts <= 1) {
            throw error;
        }
        return await retryUponFailure(wrappedFunction, attempts - 1);
    }
}
export async function resolveWithRetries(question) {
    return retryUponFailure(async () => dnssecOnlineResolve(question), RETRY_ATTEMPTS);
}
//# sourceMappingURL=resolver.js.map