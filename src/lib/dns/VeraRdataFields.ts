import { type OrganisationKeySpec } from './OrganisationKeySpec.js';

export interface VeraRdataFields extends OrganisationKeySpec {
  readonly ttlOverride: number;
  readonly serviceOid?: string;
}
