import Certificate from '../utils/x509/Certificate.js';

export interface OrganisationCertificateIssuanceOptions {
  readonly startDate: Date;
}

export async function selfIssueOrganisationCertificate(
  name: string,
  keyPair: CryptoKeyPair,
  expiryDate: Date,
  options: Partial<OrganisationCertificateIssuanceOptions> = {},
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
