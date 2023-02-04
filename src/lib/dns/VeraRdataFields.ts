import { type OrganisationKeySpec } from './organisationKeys.js';

export interface VeraRdataFields extends OrganisationKeySpec {
  readonly ttlOverride: number;
  readonly serviceOid?: string;
}
