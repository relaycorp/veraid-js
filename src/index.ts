/* eslint-disable import/no-unused-modules */

export type { TrustAnchor } from '@relaycorp/dnssec';

export { VeraidError } from './lib/VeraidError.js';

// DNS handling
export { generateTxtRdata } from './lib/dns/rdataSerialisation.js';
export { type DnsResolutionOptions, VeraidDnssecChain } from './lib/dns/VeraidDnssecChain.js';

// X.509 handling
export { selfIssueOrganisationCertificate } from './lib/pki/organisation.js';
export { issueMemberCertificate } from './lib/pki/member.js';
export type { Member } from './lib/Member.js';
export { validateUserName } from './lib/idValidation.js';
export type { CertificateIssuanceOptions } from './lib/pki/CertificateIssuanceOptions.js';
export { Certificate } from './lib/utils/x509/Certificate.js';
export { Chain } from './lib/Chain.js';
export { MemberIdBundle } from './lib/memberIdBundle/MemberIdBundle.js';
export { OrganisationSigner } from './lib/OrganisationSigner.js';

// Signature handling
export type { SignatureOptions } from './lib/SignatureOptions.js';
export type { SignatureBundleVerification } from './lib/SignatureBundleVerification.js';
export type { IDatePeriod } from './lib/dates.js';
export { SignatureBundle } from './lib/SignatureBundle.js';

// Mocking
export { MockTrustChain } from './lib/mocking/MockTrustChain.js';
export type { MockTrustChainOptions } from './lib/mocking/MockTrustChainOptions.js';
