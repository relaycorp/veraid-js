import { secondsInDay } from 'date-fns';

import VeraError from '../VeraError.js';
import { derSerializePublicKey } from '../utils/keys.js';
import { getPkijsCrypto } from '../utils/pkijs.js';
import { KeyIdType } from '../KeyIdType.js';

import { type RdataGenerationOptions } from './RdataGenerationOptions.js';
import { type VeraRdataFields } from './VeraRdataFields.js';
import { KeyAlgorithmType } from './KeyAlgorithmType.js';

const CRYPTO_ENGINE = getPkijsCrypto();

const FIELDS_REGEX = /^\s*(?<fields>\S.+\S)\s*$/u;
const FIELD_SEPARATOR_REGEX = /\s+/u;

const MAX_TTL_OVERRIDE_DAYS = 90;
const MAX_TTL_OVERRIDE_SECONDS = secondsInDay * MAX_TTL_OVERRIDE_DAYS;
const TTL_OVERRIDE_REGEX = /^\d+$/u;

const MIN_RDATA_FIELDS = 4;

const ALGORITHM_ID_BY_RSA_MODULUS: { readonly [modulus: number]: KeyAlgorithmType } = {
  // eslint-disable-next-line @typescript-eslint/naming-convention
  2048: KeyAlgorithmType.RSA_2048,
  // eslint-disable-next-line @typescript-eslint/naming-convention
  3072: KeyAlgorithmType.RSA_3072,
  // eslint-disable-next-line @typescript-eslint/naming-convention
  4096: KeyAlgorithmType.RSA_4096,
};

const ALGORITHM_ID_BY_STRING: { readonly [id: string]: KeyAlgorithmType } = {
  // eslint-disable-next-line @typescript-eslint/naming-convention
  '1': KeyAlgorithmType.RSA_2048,
  // eslint-disable-next-line @typescript-eslint/naming-convention
  '2': KeyAlgorithmType.RSA_3072,
  // eslint-disable-next-line @typescript-eslint/naming-convention
  '3': KeyAlgorithmType.RSA_4096,
};

const HASH_BY_KEY_ID_TYPE = {
  [KeyIdType.SHA256]: 'SHA-256',
  [KeyIdType.SHA384]: 'SHA-384',
  [KeyIdType.SHA512]: 'SHA-512',
};

const KEY_ID_TYPE_BY_STRING: { readonly [type: string]: KeyIdType } = {
  // eslint-disable-next-line @typescript-eslint/naming-convention
  '1': KeyIdType.SHA256,
  // eslint-disable-next-line @typescript-eslint/naming-convention
  '2': KeyIdType.SHA384,
  // eslint-disable-next-line @typescript-eslint/naming-convention
  '3': KeyIdType.SHA512,
};

function sanitiseRdata(rdata: Buffer | string | readonly Buffer[]): string {
  let rdataSanitised: string;
  if (typeof rdata === 'string') {
    rdataSanitised = rdata;
  } else if (Buffer.isBuffer(rdata)) {
    rdataSanitised = rdata.toString();
  } else {
    if (rdata.length !== 1) {
      throw new VeraError(`TXT rdata array must contain a single item (got ${rdata.length})`);
    }
    rdataSanitised = rdata[0].toString();
  }
  return rdataSanitised.replace(FIELDS_REGEX, '$<fields>');
}

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

function getAlgorithmId(algorithmString: string): KeyAlgorithmType {
  const id = ALGORITHM_ID_BY_STRING[algorithmString] as KeyAlgorithmType | undefined;
  if (!id) {
    throw new VeraError(`Unknown algorithm id ("${algorithmString}")`);
  }
  return id;
}

function getKeyIdTypeFromString(keyIdTypeString: string): KeyIdType {
  const type = KEY_ID_TYPE_BY_STRING[keyIdTypeString] as KeyIdType | undefined;
  if (!type) {
    throw new VeraError(`Unknown key id type ("${keyIdTypeString}")`);
  }
  return type;
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

function getTtlOverrideFromString(ttlOverrideString: string): number {
  if (!TTL_OVERRIDE_REGEX.test(ttlOverrideString)) {
    throw new VeraError(`Malformed TTL override ("${ttlOverrideString}")`);
  }
  const ttl = Number.parseInt(ttlOverrideString, 10);
  return Math.min(ttl, MAX_TTL_OVERRIDE_SECONDS);
}

export async function generateTxtRdata(
  orgPublicKey: CryptoKey,
  ttlOverride: number,
  options: Partial<RdataGenerationOptions> = {},
): Promise<string> {
  const algorithm = getAlgorithmIdForKey(orgPublicKey);
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

export function parseTxtRdata(rdata: Buffer | string | readonly Buffer[]): VeraRdataFields {
  const rdataSanitised = sanitiseRdata(rdata);
  const fields = rdataSanitised.split(FIELD_SEPARATOR_REGEX);
  if (fields.length < MIN_RDATA_FIELDS) {
    throw new VeraError(
      `RDATA should have at least 4 space-separated fields (got ${fields.length})`,
    );
  }

  const [algorithmString, keyIdTypeString, keyId, ttlOverrideString, serviceOid] = fields;
  const algorithm = getAlgorithmId(algorithmString);
  const keyIdType = getKeyIdTypeFromString(keyIdTypeString);
  const ttlOverride = getTtlOverrideFromString(ttlOverrideString);
  return { algorithm, keyId, keyIdType, ttlOverride, serviceOid };
}
