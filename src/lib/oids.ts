/**
 * ASN.1 Object Ids.
 */

const RELAYCORP = '1.3.6.1.4.1.58708'; // Alias: iso.org.dod.internet.private.enterprise.relaycorp
const VERAID = `${RELAYCORP}.1`;

export const VERAID_OIDS = {
  SIGNATURE_METADATA_ATTR: `${VERAID}.0`,
  TEST_SERVICE: `${VERAID}.1`,
};

export const CMS_OIDS = {
  ATTR_CONTENT_TYPE: '1.2.840.113549.1.9.3',
  ATTR_DIGEST: '1.2.840.113549.1.9.4',
  DATA: '1.2.840.113549.1.7.1',
  SIGNED_DATA: '1.2.840.113549.1.7.2',
};

export const COMMON_NAME = '2.5.4.3';

export const BASIC_CONSTRAINTS = '2.5.29.19';
export const AUTHORITY_KEY = '2.5.29.35';
export const SUBJECT_KEY = '2.5.29.14';
