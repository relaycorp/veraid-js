import Certificate from '../utils/x509/Certificate.js';
import { validateUserName } from '../idValidation.js';

import type { CertificateIssuanceOptions } from './CertificateIssuanceOptions.js';

export const BOT_NAME = '@';

export async function issueMemberCertificate(
  memberName: string | undefined,
  memberPublicKey: CryptoKey,
  organisationCertificate: Certificate,
  organisationPrivateKey: CryptoKey,
  expiryDate: Date,
  options: Partial<CertificateIssuanceOptions> = {},
): Promise<Certificate> {
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
