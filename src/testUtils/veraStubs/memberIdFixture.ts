import { type MockChainFixture, SecurityStatus } from '@relaycorp/dnssec';
import { addMinutes, setMilliseconds } from 'date-fns';

import { selfIssueOrganisationCertificate } from '../../lib/pki/organisation.js';
import { issueMemberCertificate } from '../../lib/pki/member.js';
import { DatePeriod } from '../../lib/dates.js';
import type Certificate from '../../lib/utils/x509/Certificate.js';

import { MOCK_CHAIN, VERAID_RRSET } from './dnssec.js';
import { ORG_KEY_PAIR, ORG_NAME } from './organisation.js';
import { MEMBER_KEY_PAIR, MEMBER_NAME } from './member.js';

const FIXTURE_TTL_MINUTES = 5;

interface MemberIdFixtureOptions {
  readonly orgCertificate: Certificate;
  readonly datePeriod: DatePeriod;
}

interface MemberIdFixture {
  readonly dnssecChainFixture: MockChainFixture;
  readonly orgCertificate: Certificate;
  readonly memberCertificate: Certificate;
  readonly datePeriod: DatePeriod;
}

export async function generateMemberIdFixture(
  options: Partial<MemberIdFixtureOptions> = {},
): Promise<MemberIdFixture> {
  const now = setMilliseconds(new Date(), 0);
  const datePeriod =
    options.datePeriod ?? DatePeriod.init(now, addMinutes(now, FIXTURE_TTL_MINUTES));

  const dnssecChainFixture = MOCK_CHAIN.generateFixture(VERAID_RRSET, SecurityStatus.SECURE, {
    start: datePeriod.start,
    end: datePeriod.end,
  });

  const orgCertificate =
    options.orgCertificate ??
    (await selfIssueOrganisationCertificate(ORG_NAME, ORG_KEY_PAIR, datePeriod.end, {
      startDate: datePeriod.start,
    }));

  const memberCertificate = await issueMemberCertificate(
    MEMBER_NAME,
    MEMBER_KEY_PAIR.publicKey,
    orgCertificate,
    ORG_KEY_PAIR.privateKey,
    datePeriod.end,
    { startDate: datePeriod.start },
  );

  return {
    dnssecChainFixture,
    memberCertificate,
    orgCertificate,
    datePeriod,
  };
}
