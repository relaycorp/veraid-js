import { DnsClass, DnsRecord } from '@relaycorp/dnssec';
import { secondsInDay } from 'date-fns';

import { derSerializePublicKey, generateRsaKeyPair } from '../../lib/utils/keys.js';
import { generateTxtRdata } from '../../lib/dns/rdataSerialisation.js';
import { type OrganisationKeySpec } from '../../lib/dns/OrganisationKeySpec.js';
import { KeyAlgorithmType } from '../../lib/dns/KeyAlgorithmType.js';
import { calculateDigest } from '../crypto.js';

import { ORG_DOMAIN } from './stubs.js';

export const ORG_VERA_DOMAIN = `_vera.${ORG_DOMAIN}`;

export const ORG_KEY_PAIR = await generateRsaKeyPair();

// eslint-disable-next-line @typescript-eslint/no-magic-numbers
export const TTL_OVERRIDE = 30 * secondsInDay;

export const VERA_RECORD = new DnsRecord(
  ORG_VERA_DOMAIN,
  'TXT',
  DnsClass.IN,
  // eslint-disable-next-line @typescript-eslint/no-magic-numbers
  42,
  await generateTxtRdata(ORG_KEY_PAIR.publicKey, TTL_OVERRIDE),
);

export const ORG_KEY_SPEC: OrganisationKeySpec = {
  keyAlgorithm: KeyAlgorithmType.RSA_2048,

  keyId: calculateDigest('sha256', await derSerializePublicKey(ORG_KEY_PAIR.publicKey)).toString(
    'base64',
  ),
};
