import { addDays, setMilliseconds } from 'date-fns';
import { Certificate } from '../lib/utils/x509/Certificate.js';
import { derSerializePublicKey } from '../lib/utils/keys/serialisation.js';
import { generateRsaKeyPair } from '../lib/utils/keys/generation.js';
import { calculateDigest } from './crypto.js';
/**
 * @deprecated Use {Certificate.issue} instead
 */
export async function generateStubCert(config = {}) {
    const keyPair = await generateRsaKeyPair();
    const validityEndDate = addDays(setMilliseconds(new Date(), 0), 1);
    const subjectPublicKey = config.subjectPublicKey ?? keyPair.publicKey;
    const commonName = calculateDigest('sha256', await derSerializePublicKey(subjectPublicKey)).toString('hex');
    return Certificate.issue({
        commonName,
        issuerCertificate: config.issuerCertificate,
        issuerPrivateKey: config.issuerPrivateKey ?? keyPair.privateKey,
        subjectPublicKey,
        validityEndDate,
        ...config.attributes,
    });
}
//# sourceMappingURL=pki.js.map