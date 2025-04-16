import { type Resolver, type TrustAnchor } from '@relaycorp/dnssec';
import { DatePeriod } from '../dates.js';
import type { OrganisationKeySpec } from './organisationKeys.js';
export interface DnsResolutionOptions {
    resolver?: Resolver;
    trustAnchors?: readonly TrustAnchor[];
}
export declare class VeraidDnssecChain {
    readonly domainName: string;
    readonly responses: readonly ArrayBuffer[];
    /**
     * Retrieve the DNSSEC chain for an organisation.
     * @param domainName - The domain name of the organisation to retrieve the DNSSEC chain for
     * @param options - DNS resolution options
     * @param options.resolver - The DNS resolver to use for the DNSSEC chain retrieval
     * @param options.trustAnchors - The trust anchors to use for the DNSSEC chain retrieval
     * @returns A promise that resolves to the DNSSEC chain for the organisation
     */
    static retrieve(domainName: string, { resolver, trustAnchors }?: DnsResolutionOptions): Promise<VeraidDnssecChain>;
    constructor(domainName: string, responses: readonly ArrayBuffer[]);
    /**
     * Serialise the DNSSEC chain.
     * @returns The serialised DNSSEC chain
     */
    serialise(): ArrayBuffer;
    /**
     * Verify the DNSSEC chain for an organisation.
     * @param keySpec - The key specification to use for the verification
     * @param serviceOid - The service OID to use for the verification
     * @param datePeriod - The date period to use for the verification
     * @param trustAnchors - The trust anchors to use for the verification
     */
    verify(keySpec: OrganisationKeySpec, serviceOid: string, datePeriod: DatePeriod, trustAnchors?: readonly TrustAnchor[]): Promise<void>;
}
