import { DnsClass, DnsRecord } from '@relaycorp/dnssec';

import { generateRsaKeyPair } from '../../lib/utils/keys.js';
import { generateTxtRdata, parseTxtRdata } from '../../lib/dns/rdataSerialisation.js';
import { type VeraRdataFields } from '../../lib/dns/VeraRdataFields.js';

import { ORG_DOMAIN } from './stubs.js';

export const ORG_VERA_DOMAIN = `_vera.${ORG_DOMAIN}`;

export const ORG_KEY_PAIR = await generateRsaKeyPair();

export const TTL_OVERRIDE = 42;

export const VERA_RECORD = new DnsRecord(
  ORG_VERA_DOMAIN,
  'TXT',
  DnsClass.IN,
  // eslint-disable-next-line @typescript-eslint/no-magic-numbers
  42,
  await generateTxtRdata(ORG_KEY_PAIR.publicKey, TTL_OVERRIDE),
);

export const VERA_RDATA_FIELDS: VeraRdataFields = parseTxtRdata(VERA_RECORD.dataFields as string);
