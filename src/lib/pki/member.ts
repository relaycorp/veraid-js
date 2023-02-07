import Certificate from '../utils/x509/Certificate.js';

import type { CertificateIssuanceOptions } from './CertificateIssuanceOptions.js';

export const BOT_NAME = '@';

export async function issueMemberCertificate(
  memberName: string | undefined,
  memberPublicKey: CryptoKey,
  organisationCertificate: ArrayBuffer,
  organisationPrivateKey: CryptoKey,
  expiryDate: Date,
  options: Partial<CertificateIssuanceOptions> = {},
): Promise<ArrayBuffer> {
  const issuerCertificate = Certificate.deserialize(organisationCertificate);
  const certificate = await Certificate.issue({
    commonName: memberName ?? BOT_NAME,
    subjectPublicKey: memberPublicKey,
    issuerCertificate,
    issuerPrivateKey: organisationPrivateKey,
    validityEndDate: expiryDate,
    validityStartDate: options.startDate,
  });
  return certificate.serialize();
}
