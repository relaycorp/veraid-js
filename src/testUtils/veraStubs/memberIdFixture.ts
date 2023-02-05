import { type MockChainFixture, SecurityStatus } from '@relaycorp/dnssec';
import { addMinutes, setMilliseconds } from 'date-fns';

import { selfIssueOrganisationCertificate } from '../../lib/pki/organisation.js';
import { issueMemberCertificate } from '../../lib/pki/member.js';
import { DatePeriod } from '../../lib/dates.js';

import { MOCK_CHAIN, VERA_RRSET } from './dnssec.js';
import { ORG_KEY_PAIR, ORG_NAME } from './organisation.js';
import { MEMBER_KEY_PAIR, MEMBER_NAME } from './member.js';

const FIXTURE_TTL_MINUTES = 5;

interface MemberIdFixture {
  readonly dnssecChainFixture: MockChainFixture;
  readonly orgCertificateSerialised: ArrayBuffer;
  readonly memberCertificateSerialised: ArrayBuffer;
  readonly datePeriod: DatePeriod;
}

export async function generateMemberIdFixture(
  options: Partial<MemberIdFixture> = {},
): Promise<MemberIdFixture> {
  const now = setMilliseconds(new Date(), 0);
  const datePeriod =
    options.datePeriod ?? DatePeriod.init(now, addMinutes(now, FIXTURE_TTL_MINUTES));

  const dnssecChainFixture =
    options.dnssecChainFixture ??
    MOCK_CHAIN.generateFixture(VERA_RRSET, SecurityStatus.SECURE, {
      start: datePeriod.start,
      end: datePeriod.end,
    });

  const orgCertificateSerialised =
    options.orgCertificateSerialised ??
    (await selfIssueOrganisationCertificate(ORG_NAME, ORG_KEY_PAIR, datePeriod.end, {
      startDate: datePeriod.start,
    }));

  const memberCertificateSerialised =
    options.memberCertificateSerialised ??
    (await issueMemberCertificate(
      MEMBER_NAME,
      MEMBER_KEY_PAIR.publicKey,
      orgCertificateSerialised,
      ORG_KEY_PAIR.privateKey,
      datePeriod.end,
      { startDate: datePeriod.start },
    ));

  return {
    dnssecChainFixture,
    memberCertificateSerialised,
    orgCertificateSerialised,
    datePeriod,
  };
}
