import { Chain } from './Chain.js';
/**
 * Configuration for organisation signature bundles.
 */
export class OrganisationSigner extends Chain {
    /**
     * @param dnssecChain - The DNSSEC chain for the organisation
     * @param orgCertificate - The organisation certificate
     * @param attributedMemberName - The name of the member to whom the content is attributed (optional)
     */
    constructor(dnssecChain, orgCertificate, attributedMemberName) {
        super(dnssecChain, orgCertificate);
        this.attributedMemberName = attributedMemberName;
    }
    /**
     * @internal
     */
    get signerCertificate() {
        return undefined;
    }
    /**
     * @internal
     */
    get signerName() {
        return this.attributedMemberName;
    }
}
//# sourceMappingURL=OrganisationSigner.js.map