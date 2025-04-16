import { NODE_ENGINE } from '../utils/pkijs.js';
import { derSerializePublicKey } from '../utils/keys/serialisation.js';
import { VeraidError } from '../VeraidError.js';
import { KeyAlgorithmType } from './KeyAlgorithmType.js';
const ALGORITHM_ID_BY_RSA_MODULUS = {
    // eslint-disable-next-line @typescript-eslint/naming-convention
    2048: KeyAlgorithmType.RSA_2048,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    3072: KeyAlgorithmType.RSA_3072,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    4096: KeyAlgorithmType.RSA_4096,
};
const HASH_BY_RSA_MODULUS = {
    // eslint-disable-next-line @typescript-eslint/naming-convention
    2048: 'SHA-256',
    // eslint-disable-next-line @typescript-eslint/naming-convention
    3072: 'SHA-384',
    // eslint-disable-next-line @typescript-eslint/naming-convention
    4096: 'SHA-512',
};
function getAlgorithmIdForKey(key) {
    if (key.algorithm.name !== 'RSA-PSS') {
        throw new VeraidError(`Only RSA-PSS keys are supported (got ${key.algorithm.name})`);
    }
    const { modulusLength } = key.algorithm;
    if (!(modulusLength in ALGORITHM_ID_BY_RSA_MODULUS)) {
        throw new VeraidError(`RSA key with modulus ${modulusLength} is unsupported`);
    }
    return ALGORITHM_ID_BY_RSA_MODULUS[modulusLength];
}
async function getKeyId(key) {
    const { modulusLength } = key.algorithm;
    const hashName = HASH_BY_RSA_MODULUS[modulusLength];
    const keySerialised = await derSerializePublicKey(key);
    const digest = await NODE_ENGINE.digest({ name: hashName }, keySerialised);
    return Buffer.from(digest).toString('base64');
}
export async function getKeySpec(publicKey) {
    const algorithm = getAlgorithmIdForKey(publicKey);
    const id = await getKeyId(publicKey);
    return { keyId: id, keyAlgorithm: algorithm };
}
//# sourceMappingURL=organisationKeys.js.map