import { type MockChainFixture, SecurityStatus } from '@relaycorp/dnssec';
import { addMinutes, setMilliseconds } from 'date-fns';

import { selfIssueOrganisationCertificate } from '../../lib/pki/organisation.js';
import { issueMemberCertificate } from '../../lib/pki/member.js';
import { DatePeriod } from '../../lib/utils/DatePeriod.js';

import { MOCK_CHAIN, VERA_RRSET } from './dnssec.js';
import { ORG_KEY_PAIR, ORG_NAME } from './organisation.js';
import { MEMBER_KEY_PAIR, MEMBER_NAME } from './member.js';

const FIXTURE_TTL_MINUTES = 5;

interface MemberIdFixture {
  readonly dnssecChainFixture: MockChainFixture;
  readonly organisationCertificate: ArrayBuffer;
  readonly memberCertificate: ArrayBuffer;
  readonly datePeriod: DatePeriod;
}

export async function generateMemberIdFixture(): Promise<MemberIdFixture> {
  const startDate = setMilliseconds(new Date(), 0);
  const expiryDate = addMinutes(startDate, FIXTURE_TTL_MINUTES);

  const dnssecChainFixture = MOCK_CHAIN.generateFixture(VERA_RRSET, SecurityStatus.SECURE, {
    start: startDate,
    end: expiryDate,
  });

  const organisationCertificate = await selfIssueOrganisationCertificate(
    ORG_NAME,
    ORG_KEY_PAIR,
    expiryDate,
    { startDate },
  );

  const memberCertificate = await issueMemberCertificate(
    MEMBER_NAME,
    MEMBER_KEY_PAIR.publicKey,
    organisationCertificate,
    ORG_KEY_PAIR.privateKey,
    expiryDate,
    { startDate },
  );

  return {
    dnssecChainFixture,
    memberCertificate,
    organisationCertificate,
    datePeriod: DatePeriod.init(startDate, expiryDate),
  };
}
