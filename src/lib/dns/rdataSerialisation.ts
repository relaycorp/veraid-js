import { secondsInDay } from 'date-fns';

import VeraError from '../VeraError.js';
import { derSerializePublicKey } from '../utils/keys.js';
import { getPkijsCrypto } from '../utils/pkijs.js';

import { type RdataGenerationOptions } from './RdataGenerationOptions.js';
import { KeyIdType } from './KeyIdType.js';

const CRYPTO_ENGINE = getPkijsCrypto();

const MAX_TTL_OVERRIDE_DAYS = 90;
const MAX_TTL_OVERRIDE_SECONDS = secondsInDay * MAX_TTL_OVERRIDE_DAYS;

const ALGORITHM_ID_BY_RSA_MODULUS: { readonly [modulus: number]: number } = {
  // eslint-disable-next-line @typescript-eslint/naming-convention
  2048: 0,
  // eslint-disable-next-line @typescript-eslint/naming-convention
  3072: 1,
  // eslint-disable-next-line @typescript-eslint/naming-convention
  4096: 2,
};

const HASH_BY_KEY_ID_TYPE = {
  [KeyIdType.SHA256]: 'SHA-256',
  [KeyIdType.SHA384]: 'SHA-384',
  [KeyIdType.SHA512]: 'SHA-512',
};

function getAlgorithmForKey(key: CryptoKey): number {
  if (key.algorithm.name !== 'RSA-PSS') {
    throw new VeraError(`Only RSA-PSS keys are supported (got ${key.algorithm.name})`);
  }
  const { modulusLength } = key.algorithm as RsaKeyAlgorithm;
  if (!(modulusLength in ALGORITHM_ID_BY_RSA_MODULUS)) {
    throw new VeraError(`RSA key with modulus ${modulusLength} is unsupported`);
  }
  return ALGORITHM_ID_BY_RSA_MODULUS[modulusLength];
}

async function getKeyId(orgPublicKey: CryptoKey, keyIdType: KeyIdType): Promise<string> {
  if (!(keyIdType in HASH_BY_KEY_ID_TYPE)) {
    throw new VeraError(`Unsupported key id type (${keyIdType})`);
  }
  const hashName = HASH_BY_KEY_ID_TYPE[keyIdType];
  const keySerialised = await derSerializePublicKey(orgPublicKey);
  const digest = await CRYPTO_ENGINE.digest({ name: hashName }, keySerialised);
  return Buffer.from(digest).toString('base64');
}

function validateTtlOverride(ttlOverride: number): void {
  if (ttlOverride < 0) {
    throw new VeraError(`TTL override must not be negative (got ${ttlOverride})`);
  }
  if (MAX_TTL_OVERRIDE_SECONDS < ttlOverride) {
    throw new VeraError(
      `TTL override must not exceed ${MAX_TTL_OVERRIDE_DAYS} days (got ${ttlOverride} seconds)`,
    );
  }
}

export async function generateTxtRdata(
  orgPublicKey: CryptoKey,
  ttlOverride: number,
  options: Partial<RdataGenerationOptions> = {},
): Promise<string> {
  const algorithm = getAlgorithmForKey(orgPublicKey);
  const keyIdType = options.keyIdType ?? KeyIdType.SHA256;
  const keyId = await getKeyId(orgPublicKey, keyIdType);
  validateTtlOverride(ttlOverride);
  const fields = [
    algorithm,
    keyIdType,
    keyId,
    ttlOverride,
    ...(options.serviceOid === undefined ? [] : [options.serviceOid]),
  ];
  return fields.join(' ');
}
