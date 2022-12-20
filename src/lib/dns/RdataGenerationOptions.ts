import { type KeyIdType } from './KeyIdType.js';

export interface RdataGenerationOptions {
  readonly keyIdType: KeyIdType;
  readonly serviceOid: string;
}
