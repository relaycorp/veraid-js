import { Certificate } from '../utils/x509/Certificate.js';
import type { CertificateIssuanceOptions } from './CertificateIssuanceOptions.js';
export declare function selfIssueOrganisationCertificate(name: string, keyPair: CryptoKeyPair, expiryDate: Date, options?: Partial<CertificateIssuanceOptions>): Promise<Certificate>;
