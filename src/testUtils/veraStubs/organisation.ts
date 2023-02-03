import { secondsInDay } from 'date-fns';
import { DnsClass, DnsRecord } from '@relaycorp/dnssec';

import { derSerializePublicKey } from '../../lib/utils/keys/serialisation.js';
import { type OrganisationKeySpec } from '../../lib/dns/organisationKeys.js';
import { KeyAlgorithmType } from '../../lib/dns/KeyAlgorithmType.js';
import { calculateDigest } from '../crypto.js';
import { generateTxtRdata } from '../../lib/dns/rdataSerialisation.js';
import { generateRsaKeyPair } from '../../lib/utils/keys/generation.js';

const VERA_RECORD_TTL = 42;

export const ORG_NAME = 'example.com';
export const ORG_DOMAIN = `${ORG_NAME}.`;
export const ORG_VERA_DOMAIN = `_vera.${ORG_DOMAIN}`;
export const ORG_KEY_PAIR = await generateRsaKeyPair();
// eslint-disable-next-line @typescript-eslint/no-magic-numbers
export const VERA_RECORD_TTL_OVERRIDE = 30 * secondsInDay;
export const VERA_RECORD = new DnsRecord(
  ORG_VERA_DOMAIN,
  'TXT',
  DnsClass.IN,
  VERA_RECORD_TTL,
  await generateTxtRdata(ORG_KEY_PAIR.publicKey, VERA_RECORD_TTL_OVERRIDE),
);
export const ORG_KEY_SPEC: OrganisationKeySpec = {
  keyAlgorithm: KeyAlgorithmType.RSA_2048,

  keyId: calculateDigest('sha256', await derSerializePublicKey(ORG_KEY_PAIR.publicKey)).toString(
    'base64',
  ),
};
