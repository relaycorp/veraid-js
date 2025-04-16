import { CryptoEngine } from 'pkijs';
import { NODE_ENGINE } from '../pkijs.js';
import { VeraCrypto } from './VeraCrypto.js';
const ENGINE_BY_PROVIDER = new WeakMap();
/**
 * Generate and cache PKI.js engine for specified private key.
 */
export function getEngineForPrivateKey(privateKey) {
    const provider = privateKey.provider;
    if (!provider) {
        return NODE_ENGINE;
    }
    const cachedEngine = ENGINE_BY_PROVIDER.get(provider);
    if (cachedEngine) {
        return cachedEngine;
    }
    const crypto = new VeraCrypto([provider]);
    const engine = new CryptoEngine({ crypto });
    ENGINE_BY_PROVIDER.set(provider, engine);
    return engine;
}
//# sourceMappingURL=engine.js.map