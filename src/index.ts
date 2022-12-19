/* eslint-disable import/no-unused-modules */
import { CryptoEngine, setEngine } from 'pkijs';

import { VeraCrypto } from './lib/utils/webcrypto/VeraCrypto.js';

const crypto = new VeraCrypto();
const cryptoEngine = new CryptoEngine({ crypto, name: 'nodeEngine' });
setEngine('nodeEngine', cryptoEngine);

export {
  selfIssueOrganisationCertificate,
  type OrganisationCertificateIssuanceOptions,
} from './lib/pki/organisation.js';
