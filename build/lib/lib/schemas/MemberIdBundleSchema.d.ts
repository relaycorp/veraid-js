import { Certificate } from '@peculiar/asn1-x509';
import { DnssecChainSchema } from './DnssecChainSchema.js';
export declare class MemberIdBundleSchema {
    version: number;
    dnssecChain: DnssecChainSchema;
    organisationCertificate: Certificate;
    memberCertificate: Certificate;
}
