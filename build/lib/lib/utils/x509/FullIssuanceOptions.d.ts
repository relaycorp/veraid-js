import type { Certificate } from './Certificate.js';
export default interface FullIssuanceOptions {
    readonly issuerPrivateKey: CryptoKey;
    readonly subjectPublicKey: CryptoKey;
    readonly validityStartDate?: Date;
    readonly validityEndDate: Date;
    readonly isCa?: boolean;
    readonly commonName: string;
    readonly issuerCertificate?: Certificate;
    readonly pathLenConstraint?: number;
}
