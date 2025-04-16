import { Certificate } from '../utils/x509/Certificate.js';
export async function selfIssueOrganisationCertificate(name, keyPair, expiryDate, options = {}) {
    return Certificate.issue({
        commonName: name,
        subjectPublicKey: keyPair.publicKey,
        issuerPrivateKey: keyPair.privateKey,
        validityEndDate: expiryDate,
        validityStartDate: options.startDate,
        isCa: true,
    });
}
//# sourceMappingURL=organisation.js.map