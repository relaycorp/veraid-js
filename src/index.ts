/* eslint-disable import/no-unused-modules */
import { CryptoEngine, setEngine } from 'pkijs';

import { VeraCrypto } from './lib/utils/webcrypto/VeraCrypto.js';

const crypto = new VeraCrypto();
const cryptoEngine = new CryptoEngine({ crypto, name: 'nodeEngine' });
setEngine('nodeEngine', cryptoEngine);

export { issueMemberCertificate } from './lib/pki/member.js';
export { selfIssueOrganisationCertificate } from './lib/pki/organisation.js';
export type { CertificateIssuanceOptions } from './lib/pki/CertificateIssuanceOptions.js';