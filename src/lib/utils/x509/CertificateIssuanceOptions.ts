import type Certificate from './Certificate.js';

export default interface CertificateIssuanceOptions {
  readonly issuerPrivateKey: CryptoKey;
  readonly subjectPublicKey: CryptoKey;
  readonly validityStartDate?: Date;
  readonly validityEndDate: Date;
  readonly isCa?: boolean; // Basic Constraints extension
  readonly commonName: string;
  readonly issuerCertificate?: Certificate; // Absent when self-signed
  readonly pathLenConstraint?: number; // Basic Constraints extension
}
