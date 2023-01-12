import { type KeyIdType } from '../KeyIdType.js';

import { type KeyAlgorithmType } from './KeyAlgorithmType.js';

export interface VeraRdataFields {
  readonly algorithm: KeyAlgorithmType;
  readonly keyIdType: KeyIdType;
  readonly keyId: string;
  readonly ttlOverride: number;
  readonly serviceOid?: string;
}
