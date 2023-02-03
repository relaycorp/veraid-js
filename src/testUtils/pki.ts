import { addDays, setMilliseconds } from 'date-fns';

import Certificate from '../lib/utils/x509/Certificate.js';
import { derSerializePublicKey } from '../lib/utils/keys/serialisation.js';
import type FullIssuanceOptions from '../lib/utils/x509/FullIssuanceOptions.js';
import { generateRsaKeyPair } from '../lib/utils/keys/generation.js';

import { calculateDigest } from './crypto.js';

interface StubCertConfig {
  readonly attributes: Partial<FullIssuanceOptions>;
  readonly issuerCertificate: Certificate;
  readonly issuerPrivateKey: CryptoKey;
  readonly subjectPublicKey: CryptoKey;
}

/**
 * @deprecated Use {Certificate.issue} instead
 */
export async function generateStubCert(config: Partial<StubCertConfig> = {}): Promise<Certificate> {
  const keyPair = await generateRsaKeyPair();
  const validityEndDate = addDays(setMilliseconds(new Date(), 0), 1);
  const subjectPublicKey = config.subjectPublicKey ?? keyPair.publicKey;
  const commonName = calculateDigest(
    'sha256',
    await derSerializePublicKey(subjectPublicKey),
  ).toString('hex');
  return Certificate.issue({
    commonName,
    issuerCertificate: config.issuerCertificate,
    issuerPrivateKey: config.issuerPrivateKey ?? keyPair.privateKey,
    subjectPublicKey,
    validityEndDate,
    ...config.attributes,
  });
}
