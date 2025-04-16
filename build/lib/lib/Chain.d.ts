import type { TrustAnchor } from '@relaycorp/dnssec';
import type { DatePeriod } from './dates.js';
import type { Certificate } from './utils/x509/Certificate.js';
import type { VeraidDnssecChain } from './dns/VeraidDnssecChain.js';
import type { Member } from './Member.js';
export declare abstract class Chain {
    readonly dnssecChain: VeraidDnssecChain;
    readonly orgCertificate: Certificate;
    protected constructor(dnssecChain: VeraidDnssecChain, orgCertificate: Certificate);
    /**
     * Verify the chain and return the member information.
     * @param serviceOid - The service OID to verify
     * @param datePeriod - The date period to verify
     * @param dnssecTrustAnchors - The DNSSEC trust anchors to use for verification
     * @returns The member information
     */
    verify(serviceOid: string, datePeriod: DatePeriod, dnssecTrustAnchors?: readonly TrustAnchor[]): Promise<Member>;
}
