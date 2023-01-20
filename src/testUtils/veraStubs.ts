import { DnsClass, DnsRecord } from '@relaycorp/dnssec';

export const ORG_NAME = 'example.com';
export const ORG_DOMAIN = `${ORG_NAME}.`;
export const ORG_VERA_DOMAIN = `_vera.${ORG_DOMAIN}`;

export const MEMBER_NAME = 'alice';
export const SERVICE_OID = '1.2.3.4.5';

export const VERA_RECORD = new DnsRecord(
  ORG_VERA_DOMAIN,
  'TXT',
  DnsClass.IN,
  // eslint-disable-next-line @typescript-eslint/no-magic-numbers
  42,
  'foo' as unknown as object,
);
