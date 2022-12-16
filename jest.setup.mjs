import { Crypto } from '@peculiar/webcrypto';
import { CryptoEngine, setEngine } from 'pkijs';

const crypto = new Crypto();
const cryptoEngine = new CryptoEngine({
  crypto,
  name: 'nodeEngine',
  subtle: crypto.subtle,
});
setEngine('nodeEngine', crypto, cryptoEngine);
