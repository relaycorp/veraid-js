import { Certificate } from '../lib/utils/x509/Certificate.js';
import type FullIssuanceOptions from '../lib/utils/x509/FullIssuanceOptions.js';
interface StubCertConfig {
    readonly attributes: Partial<FullIssuanceOptions>;
    readonly issuerCertificate: Certificate;
    readonly issuerPrivateKey: CryptoKey;
    readonly subjectPublicKey: CryptoKey;
}
/**
 * @deprecated Use {Certificate.issue} instead
 */
export declare function generateStubCert(config?: Partial<StubCertConfig>): Promise<Certificate>;
export {};
