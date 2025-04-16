import { DnsRecord } from '@relaycorp/dnssec';
import type { OrganisationKeySpec } from '../../lib/dns/organisationKeys.js';
export declare const ORG_NAME = "example.com";
export declare const ORG_DOMAIN = "example.com.";
export declare const ORG_VERAID_DOMAIN = "_veraid.example.com.";
export declare const ORG_KEY_PAIR: CryptoKeyPair;
export declare const VERAID_RECORD_TTL_OVERRIDE: number;
export declare const VERAID_RECORD: DnsRecord;
export declare const ORG_KEY_SPEC: OrganisationKeySpec;
