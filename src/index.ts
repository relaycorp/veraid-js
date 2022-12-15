import { CryptoEngine, setEngine } from 'pkijs';

import { VeraCrypto } from './lib/crypto_wrappers/webcrypto/VeraCrypto.js';

const crypto = new VeraCrypto();
const cryptoEngine = new CryptoEngine({
  crypto,
  name: 'nodeEngine',
  subtle: crypto.subtle,
});
setEngine('nodeEngine', cryptoEngine);
