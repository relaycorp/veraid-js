import { type KeyAlgorithmType } from './KeyAlgorithmType.js';

export interface VeraRdataFields {
  readonly keyAlgorithm: KeyAlgorithmType;
  readonly keyId: string;
  readonly ttlOverride: number;
  readonly serviceOid?: string;
}
