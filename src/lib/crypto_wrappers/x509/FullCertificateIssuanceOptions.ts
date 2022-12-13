import type BasicCertificateIssuanceOptions from './BasicCertificateIssuanceOptions.js';
import type Certificate from './Certificate.js';

export default interface FullCertificateIssuanceOptions extends BasicCertificateIssuanceOptions {
  readonly isCa?: boolean; // Basic Constraints extension
  readonly commonName: string;
  readonly issuerCertificate?: Certificate; // Absent when self-signed
  readonly pathLenConstraint?: number; // Basic Constraints extension
}
