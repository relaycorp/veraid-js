import { getCrypto, type ICryptoEngine } from 'pkijs';

export function getPkijsCrypto(): ICryptoEngine {
  const cryptoEngine = getCrypto();
  if (!cryptoEngine) {
    throw new Error('PKI.js crypto engine is undefined');
  }
  return cryptoEngine;
}
