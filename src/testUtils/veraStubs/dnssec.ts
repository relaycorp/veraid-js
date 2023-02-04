import { MockChain, RrSet } from '@relaycorp/dnssec';

import { ORG_DOMAIN, VERA_RECORD } from './organisation.js';

export const MOCK_CHAIN = await MockChain.generate(ORG_DOMAIN);
export const VERA_RRSET = RrSet.init(VERA_RECORD.makeQuestion(), [VERA_RECORD]);
