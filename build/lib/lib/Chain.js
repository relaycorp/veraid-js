import { VeraidError } from './VeraidError.js';
import { getKeySpec } from './dns/organisationKeys.js';
import { validateUserName } from './idValidation.js';
/**
 * Verify the certificate chain and return the intersection of the validity periods.
 */
async function verifyCertificateChain(orgCertificate, signerCertificate, datePeriod) {
    let certChain;
    try {
        certChain = await signerCertificate.getCertificationPath([], [orgCertificate]);
    }
    catch (err) {
        throw new VeraidError('Member certificate was not issued by organisation', { cause: err });
    }
    const certChainPeriod = certChain
        .map((certificate) => certificate.validityPeriod)
        .reduce((previousValue, currentValue) => previousValue.intersect(currentValue));
    const intersection = certChainPeriod.intersect(datePeriod);
    if (!intersection) {
        throw new VeraidError(`Validity period of certificate chain (${certChainPeriod.toString()}) ` +
            `does not overlap with required period (${datePeriod.toString()})`);
    }
    return intersection;
}
export class Chain {
    constructor(dnssecChain, orgCertificate) {
        this.dnssecChain = dnssecChain;
        this.orgCertificate = orgCertificate;
    }
    /**
     * Verify the chain and return the member information.
     * @param serviceOid - The service OID to verify
     * @param datePeriod - The date period to verify
     * @param dnssecTrustAnchors - The DNSSEC trust anchors to use for verification
     * @returns The member information
     */
    async verify(serviceOid, datePeriod, dnssecTrustAnchors) {
        const signerCertificate = this.signerCertificate ?? this.orgCertificate;
        const certChainPeriod = await verifyCertificateChain(this.orgCertificate, signerCertificate, datePeriod);
        const keySpec = await getKeySpec(await this.orgCertificate.getPublicKey());
        await this.dnssecChain.verify(keySpec, serviceOid, certChainPeriod, dnssecTrustAnchors);
        const organisation = this.orgCertificate.commonName.replace(/\.$/u, '');
        const user = this.signerName;
        if (user !== undefined) {
            validateUserName(user);
        }
        return { organisation, user };
    }
}
//# sourceMappingURL=Chain.js.map