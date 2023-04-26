import { CryptoEngine } from 'pkijs';

import { VeraCrypto } from './webcrypto/VeraCrypto.js';

const crypto = new VeraCrypto();
export const NODE_ENGINE = new CryptoEngine({ crypto, name: 'nodeEngine' });
