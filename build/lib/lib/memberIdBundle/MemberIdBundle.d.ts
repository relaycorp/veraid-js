import { Certificate } from '../utils/x509/Certificate.js';
import { Chain } from '../Chain.js';
import { VeraidDnssecChain } from '../dns/VeraidDnssecChain.js';
/**
 * VeraId member identity bundle containing certificates and DNSSEC chain
 */
export declare class MemberIdBundle extends Chain {
    readonly memberCertificate: Certificate;
    /**
     * Deserialise a member id bundle from its binary representation
     * @param memberIdBundleSerialised - The serialised member id bundle
     * @returns A new MemberIdBundle instance
     * @throws If the bundle is malformed
     */
    static deserialise(memberIdBundleSerialised: ArrayBuffer): MemberIdBundle;
    constructor(dnssecChain: VeraidDnssecChain, orgCertificate: Certificate, memberCertificate: Certificate);
    /**
     * Serialise this member id bundle to its binary representation
     * @returns The serialised member id bundle
     */
    serialise(): ArrayBuffer;
}
