import { Certificate } from '../utils/x509/Certificate.js';
import type { CertificateIssuanceOptions } from './CertificateIssuanceOptions.js';
export declare const BOT_NAME = "@";
export declare function issueMemberCertificate(memberName: string | undefined, memberPublicKey: CryptoKey, organisationCertificate: Certificate, organisationPrivateKey: CryptoKey, expiryDate: Date, options?: Partial<CertificateIssuanceOptions>): Promise<Certificate>;
