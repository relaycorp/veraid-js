import Certificate from '../utils/x509/Certificate.js';

import { type CertificateIssuanceOptions } from './CertificateIssuanceOptions.js';

export async function selfIssueOrganisationCertificate(
  name: string,
  keyPair: CryptoKeyPair,
  expiryDate: Date,
  options: Partial<CertificateIssuanceOptions> = {},
): Promise<ArrayBuffer> {
  const certificate = await Certificate.issue({
    commonName: name,
    subjectPublicKey: keyPair.publicKey,
    issuerPrivateKey: keyPair.privateKey,
    validityEndDate: expiryDate,
    validityStartDate: options.startDate,
    isCa: true,
  });
  return certificate.serialize();
}
