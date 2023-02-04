import { getPkijsCrypto } from '../utils/pkijs.js';
import { derSerializePublicKey } from '../utils/keys/serialisation.js';
import VeraError from '../VeraError.js';

import { KeyAlgorithmType } from './KeyAlgorithmType.js';

const CRYPTO_ENGINE = getPkijsCrypto();

const ALGORITHM_ID_BY_RSA_MODULUS: { readonly [modulus: number]: KeyAlgorithmType } = {
  // eslint-disable-next-line @typescript-eslint/naming-convention
  2048: KeyAlgorithmType.RSA_2048,
  // eslint-disable-next-line @typescript-eslint/naming-convention
  3072: KeyAlgorithmType.RSA_3072,
  // eslint-disable-next-line @typescript-eslint/naming-convention
  4096: KeyAlgorithmType.RSA_4096,
};
const HASH_BY_RSA_MODULUS: { readonly [modulus: number]: string } = {
  // eslint-disable-next-line @typescript-eslint/naming-convention
  2048: 'SHA-256',
  // eslint-disable-next-line @typescript-eslint/naming-convention
  3072: 'SHA-384',
  // eslint-disable-next-line @typescript-eslint/naming-convention
  4096: 'SHA-512',
};

function getAlgorithmIdForKey(key: CryptoKey): number {
  if (key.algorithm.name !== 'RSA-PSS') {
    throw new VeraError(`Only RSA-PSS keys are supported (got ${key.algorithm.name})`);
  }
  const { modulusLength } = key.algorithm as RsaKeyAlgorithm;
  if (!(modulusLength in ALGORITHM_ID_BY_RSA_MODULUS)) {
    throw new VeraError(`RSA key with modulus ${modulusLength} is unsupported`);
  }
  return ALGORITHM_ID_BY_RSA_MODULUS[modulusLength];
}

async function getKeyId(key: CryptoKey): Promise<string> {
  const { modulusLength } = key.algorithm as RsaKeyAlgorithm;
  const hashName = HASH_BY_RSA_MODULUS[modulusLength];
  const keySerialised = await derSerializePublicKey(key);

  const digest = await CRYPTO_ENGINE.digest({ name: hashName }, keySerialised);
  return Buffer.from(digest).toString('base64');
}

export interface OrganisationKeySpec {
  readonly keyAlgorithm: KeyAlgorithmType;
  readonly keyId: string;
}

export async function getKeySpec(publicKey: CryptoKey): Promise<OrganisationKeySpec> {
  const algorithm = getAlgorithmIdForKey(publicKey);
  const id = await getKeyId(publicKey);
  return { keyId: id, keyAlgorithm: algorithm };
}
