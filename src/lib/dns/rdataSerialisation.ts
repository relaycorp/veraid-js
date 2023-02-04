import { secondsInDay } from 'date-fns';

import VeraError from '../VeraError.js';

import { type VeraRdataFields } from './VeraRdataFields.js';
import { KeyAlgorithmType } from './KeyAlgorithmType.js';
import { getKeySpec } from './organisationKeys.js';

const FIELDS_REGEX = /^\s*(?<fields>\S.+\S)\s*$/u;
const FIELD_SEPARATOR_REGEX = /\s+/u;

const MAX_TTL_OVERRIDE_DAYS = 90;
const MAX_TTL_OVERRIDE_SECONDS = secondsInDay * MAX_TTL_OVERRIDE_DAYS;
const TTL_OVERRIDE_REGEX = /^\d+$/u;

const MIN_RDATA_FIELDS = 3;

const ALGORITHM_ID_BY_STRING: { readonly [id: string]: KeyAlgorithmType } = {
  // eslint-disable-next-line @typescript-eslint/naming-convention
  '1': KeyAlgorithmType.RSA_2048,
  // eslint-disable-next-line @typescript-eslint/naming-convention
  '2': KeyAlgorithmType.RSA_3072,
  // eslint-disable-next-line @typescript-eslint/naming-convention
  '3': KeyAlgorithmType.RSA_4096,
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

function getAlgorithmId(algorithmString: string): KeyAlgorithmType {
  const id = ALGORITHM_ID_BY_STRING[algorithmString] as KeyAlgorithmType | undefined;
  if (!id) {
    throw new VeraError(`Unknown algorithm id ("${algorithmString}")`);
  }
  return id;
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
  serviceOid?: string,
): Promise<string> {
  const keySpec = await getKeySpec(orgPublicKey);
  validateTtlOverride(ttlOverride);
  const optionalFields = serviceOid === undefined ? [] : [serviceOid];
  const fields = [keySpec.keyAlgorithm, keySpec.keyId, ttlOverride, ...optionalFields];
  return fields.join(' ');
}

export function parseTxtRdata(rdata: Buffer | string | readonly Buffer[]): VeraRdataFields {
  const rdataSanitised = sanitiseRdata(rdata);
  const fields = rdataSanitised.split(FIELD_SEPARATOR_REGEX);
  if (fields.length < MIN_RDATA_FIELDS) {
    throw new VeraError(
      `RDATA should have at least 3 space-separated fields (got ${fields.length})`,
    );
  }

  const [algorithmString, keyId, ttlOverrideString, serviceOid] = fields;
  const algorithm = getAlgorithmId(algorithmString);
  const ttlOverride = getTtlOverrideFromString(ttlOverrideString);
  return { keyAlgorithm: algorithm, keyId, ttlOverride, serviceOid };
}
