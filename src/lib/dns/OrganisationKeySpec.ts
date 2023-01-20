import { type KeyAlgorithmType } from './KeyAlgorithmType.js';

export interface OrganisationKeySpec {
  readonly keyAlgorithm: KeyAlgorithmType;
  readonly keyId: string;
}
