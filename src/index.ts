import { CryptoEngine, setEngine } from 'pkijs';

import { AwalaCrypto } from './lib/crypto_wrappers/webcrypto/AwalaCrypto.js';

const crypto = new AwalaCrypto();
const cryptoEngine = new CryptoEngine({
  crypto,
  name: 'nodeEngine',
  subtle: crypto.subtle,
});
setEngine('nodeEngine', cryptoEngine);
