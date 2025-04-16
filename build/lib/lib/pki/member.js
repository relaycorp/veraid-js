import { Certificate } from '../utils/x509/Certificate.js';
import { validateUserName } from '../idValidation.js';
export const BOT_NAME = '@';
export async function issueMemberCertificate(memberName, memberPublicKey, organisationCertificate, organisationPrivateKey, expiryDate, options = {}) {
    if (memberName !== undefined) {
        validateUserName(memberName);
    }
    return Certificate.issue({
        commonName: memberName ?? BOT_NAME,
        subjectPublicKey: memberPublicKey,
        issuerCertificate: organisationCertificate,
        issuerPrivateKey: organisationPrivateKey,
        validityEndDate: expiryDate,
        validityStartDate: options.startDate,
    });
}
//# sourceMappingURL=member.js.map