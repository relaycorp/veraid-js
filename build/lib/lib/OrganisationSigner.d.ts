import { Chain } from './Chain.js';
import type { VeraidDnssecChain } from './dns/VeraidDnssecChain.js';
import type { Certificate } from './utils/x509/Certificate.js';
/**
 * Configuration for organisation signature bundles.
 */
export declare class OrganisationSigner extends Chain {
    readonly attributedMemberName?: string | undefined;
    /**
     * @param dnssecChain - The DNSSEC chain for the organisation
     * @param orgCertificate - The organisation certificate
     * @param attributedMemberName - The name of the member to whom the content is attributed (optional)
     */
    constructor(dnssecChain: VeraidDnssecChain, orgCertificate: Certificate, attributedMemberName?: string | undefined);
}
