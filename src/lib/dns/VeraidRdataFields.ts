import type { OrganisationKeySpec } from './organisationKeys.js';

export interface VeraidRdataFields extends OrganisationKeySpec {
  readonly ttlOverride: number;
  readonly serviceOid?: string;
}
