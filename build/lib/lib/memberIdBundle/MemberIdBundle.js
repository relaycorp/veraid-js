import { AsnParser, AsnSerializer } from '@peculiar/asn1-schema';
import { Certificate } from '../utils/x509/Certificate.js';
import { VeraidError } from '../VeraidError.js';
import { MemberIdBundleSchema } from '../schemas/MemberIdBundleSchema.js';
import { BOT_NAME } from '../pki/member.js';
import { Chain } from '../Chain.js';
import { VeraidDnssecChain } from '../dns/VeraidDnssecChain.js';
/**
 * VeraId member identity bundle containing certificates and DNSSEC chain
 */
export class MemberIdBundle extends Chain {
    /**
     * Deserialise a member id bundle from its binary representation
     * @param memberIdBundleSerialised - The serialised member id bundle
     * @returns A new MemberIdBundle instance
     * @throws If the bundle is malformed
     */
    static deserialise(memberIdBundleSerialised) {
        let memberIdBundleSchema;
        try {
            memberIdBundleSchema = AsnParser.parse(memberIdBundleSerialised, MemberIdBundleSchema);
        }
        catch {
            throw new VeraidError('Member id bundle is malformed');
        }
        return this.fromSchema(memberIdBundleSchema);
    }
    /**
     * Create a MemberIdBundle instance from an ASN.1 schema
     * @internal
     * @param schema - The ASN.1 schema representation of a member id bundle
     * @returns A new MemberIdBundle instance
     */
    static fromSchema(schema) {
        const orgCertificate = Certificate.fromSchema(schema.organisationCertificate);
        const dnssecChain = new VeraidDnssecChain(orgCertificate.commonName, schema.dnssecChain);
        const memberCertificate = Certificate.fromSchema(schema.memberCertificate);
        return new MemberIdBundle(dnssecChain, orgCertificate, memberCertificate);
    }
    constructor(dnssecChain, orgCertificate, memberCertificate) {
        super(dnssecChain, orgCertificate);
        this.memberCertificate = memberCertificate;
    }
    /**
     * Serialise this member id bundle to its binary representation
     * @returns The serialised member id bundle
     */
    serialise() {
        const schema = this.toSchema();
        return AsnSerializer.serialize(schema);
    }
    /**
     * Convert a MemberIdBundle instance to its ASN.1 schema representation
     * @internal
     * @returns The ASN.1 schema representation of the member id bundle
     */
    toSchema() {
        const bundle = new MemberIdBundleSchema();
        bundle.version = 0;
        bundle.memberCertificate = this.memberCertificate.toSchema();
        bundle.organisationCertificate = this.orgCertificate.toSchema();
        bundle.dnssecChain = this.dnssecChain.toSchema();
        return bundle;
    }
    /**
     * @internal
     */
    get signerCertificate() {
        return this.memberCertificate;
    }
    /**
     * @internal
     */
    get signerName() {
        return this.memberCertificate.commonName === BOT_NAME
            ? undefined
            : this.memberCertificate.commonName;
    }
}
//# sourceMappingURL=MemberIdBundle.js.map