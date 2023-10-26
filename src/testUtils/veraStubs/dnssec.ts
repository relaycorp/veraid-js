import { MockChain, RrSet } from '@relaycorp/dnssec';

import { ORG_DOMAIN, VERAID_RECORD } from './organisation.js';

export const MOCK_CHAIN = await MockChain.generate(ORG_DOMAIN);
export const VERAID_RRSET = RrSet.init(VERAID_RECORD.makeQuestion(), [VERAID_RECORD]);
