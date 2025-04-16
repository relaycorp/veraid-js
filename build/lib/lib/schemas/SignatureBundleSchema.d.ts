import { ContentInfo } from '@peculiar/asn1-cms';
import { Certificate } from '@peculiar/asn1-x509';
import { DnssecChainSchema } from './DnssecChainSchema.js';
export declare class SignatureBundleSchema {
    version: number;
    dnssecChain: DnssecChainSchema;
    organisationCertificate: Certificate;
    signature: ContentInfo;
}
