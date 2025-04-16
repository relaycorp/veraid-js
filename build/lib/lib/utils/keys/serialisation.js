import { NODE_ENGINE } from '../pkijs.js';
import { bufferToArray } from '../buffers.js';
import { PrivateKey } from './PrivateKey.js';
const DEFAULT_RSA_KEY_PARAMS = {
    hash: { name: 'SHA-256' },
    name: 'RSA-PSS',
};
/**
 * Return DER serialization of public key.
 */
export async function derSerializePublicKey(publicKey) {
    const publicKeyDer = publicKey instanceof PrivateKey
        ? (await publicKey.provider.exportKey('spki', publicKey))
        : await NODE_ENGINE.exportKey('spki', publicKey);
    return Buffer.from(publicKeyDer);
}
/**
 * Return DER serialization of private key.
 */
export async function derSerializePrivateKey(privateKey) {
    const keyDer = await NODE_ENGINE.exportKey('pkcs8', privateKey);
    return Buffer.from(keyDer);
}
/**
 * Parse DER-serialized RSA public key.
 */
export async function derDeserializeRsaPublicKey(publicKeyDer, algorithmOptions = DEFAULT_RSA_KEY_PARAMS) {
    const keyData = publicKeyDer instanceof Buffer ? bufferToArray(publicKeyDer) : publicKeyDer;
    return NODE_ENGINE.importKey('spki', keyData, algorithmOptions, true, ['verify']);
}
/**
 * Parse DER-serialized RSA private key.
 */
export async function derDeserializeRsaPrivateKey(privateKeyDer, algorithmOptions = DEFAULT_RSA_KEY_PARAMS) {
    return NODE_ENGINE.importKey('pkcs8', bufferToArray(privateKeyDer), algorithmOptions, true, [
        'sign',
    ]);
}
//# sourceMappingURL=serialisation.js.map