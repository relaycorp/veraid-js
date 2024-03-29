import { secondsInDay } from 'date-fns';
import { DnsClass, DnsRecord } from '@relaycorp/dnssec';

import { derSerializePublicKey } from '../../lib/utils/keys/serialisation.js';
import type { OrganisationKeySpec } from '../../lib/dns/organisationKeys.js';
import { KeyAlgorithmType } from '../../lib/dns/KeyAlgorithmType.js';
import { calculateDigest } from '../crypto.js';
import { generateTxtRdata } from '../../lib/dns/rdataSerialisation.js';
import { generateRsaKeyPair } from '../../lib/utils/keys/generation.js';

const RECORD_TTL = 42;
const RECORD_TTL_OVERRIDE_DAYS = 30;

export const ORG_NAME = 'example.com';
export const ORG_DOMAIN = `${ORG_NAME}.`;
export const ORG_VERAID_DOMAIN = `_veraid.${ORG_DOMAIN}`;
export const ORG_KEY_PAIR = await generateRsaKeyPair();
export const VERAID_RECORD_TTL_OVERRIDE = RECORD_TTL_OVERRIDE_DAYS * secondsInDay;
export const VERAID_RECORD = new DnsRecord(
  ORG_VERAID_DOMAIN,
  'TXT',
  DnsClass.IN,
  RECORD_TTL,
  await generateTxtRdata(ORG_KEY_PAIR.publicKey, VERAID_RECORD_TTL_OVERRIDE),
);
export const ORG_KEY_SPEC: OrganisationKeySpec = {
  keyAlgorithm: KeyAlgorithmType.RSA_2048,

  keyId: calculateDigest('sha256', await derSerializePublicKey(ORG_KEY_PAIR.publicKey)).toString(
    'base64',
  ),
};
