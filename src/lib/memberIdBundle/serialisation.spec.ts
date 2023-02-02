import { MockChain, RrSet, SecurityStatus } from '@relaycorp/dnssec';
import { AsnParser, AsnSerializer } from '@peculiar/asn1-schema';
import { addMinutes, setMilliseconds, subMinutes } from 'date-fns';

import { MEMBER_KEY_PAIR, MEMBER_NAME } from '../../testUtils/veraStubs/member.js';
import { arrayBufferFrom } from '../../testUtils/buffers.js';
import { selfIssueOrganisationCertificate } from '../pki/organisation.js';
import { issueMemberCertificate } from '../pki/member.js';
import { DnssecChainSchema } from '../dns/DnssecChainSchema.js';
import VeraError from '../VeraError.js';
import {
  ORG_DOMAIN,
  ORG_KEY_PAIR,
  ORG_NAME,
  VERA_RECORD,
} from '../../testUtils/veraStubs/organisation.js';

import { serialiseMemberIdBundle } from './serialisation.js';
import { MemberIdBundleSchema } from './MemberIdBundleSchema.js';

let orgCertificate: ArrayBuffer;
let memberCertificate: ArrayBuffer;
beforeAll(async () => {
  const now = setMilliseconds(new Date(), 0);
  const startDate = subMinutes(now, 5);
  const expiryDate = addMinutes(now, 5);

  orgCertificate = await selfIssueOrganisationCertificate(ORG_NAME, ORG_KEY_PAIR, expiryDate, {
    startDate,
  });

  memberCertificate = await issueMemberCertificate(
    MEMBER_NAME,
    MEMBER_KEY_PAIR.publicKey,
    orgCertificate,
    ORG_KEY_PAIR.privateKey,
    expiryDate,
  );
});

let dnssecChainSerialised: ArrayBuffer;
beforeAll(async () => {
  const mockChain = await MockChain.generate(ORG_DOMAIN);
  const rrset = RrSet.init(VERA_RECORD.makeQuestion(), [VERA_RECORD]);
  const { responses } = mockChain.generateFixture(rrset, SecurityStatus.SECURE);
  const dnssecChain = new DnssecChainSchema(responses.map((response) => response.serialise()));
  dnssecChainSerialised = AsnSerializer.serialize(dnssecChain);
});

describe('serialiseMemberIdBundle', () => {
  test('Malformed member certificate should be refused', () => {
    expect(() =>
      serialiseMemberIdBundle(arrayBufferFrom('malformed'), orgCertificate, dnssecChainSerialised),
    ).toThrowWithMessage(VeraError, 'Member certificate is malformed');
  });

  test('Malformed organisation certificate should be refused', () => {
    expect(() =>
      serialiseMemberIdBundle(
        memberCertificate,
        arrayBufferFrom('malformed'),
        dnssecChainSerialised,
      ),
    ).toThrowWithMessage(VeraError, 'Organisation certificate is malformed');
  });

  test('Malformed DNSSEC chain should be refused', () => {
    expect(() =>
      serialiseMemberIdBundle(memberCertificate, orgCertificate, arrayBufferFrom('malformed')),
    ).toThrowWithMessage(VeraError, 'DNSSEC chain is malformed');
  });

  test('Well-formed bundle should be output', () => {
    const bundleSerialised = serialiseMemberIdBundle(
      memberCertificate,
      orgCertificate,
      dnssecChainSerialised,
    );

    const bundle = AsnParser.parse(bundleSerialised, MemberIdBundleSchema);
    expect(Buffer.from(AsnSerializer.serialize(bundle.dnssecChain))).toStrictEqual(
      Buffer.from(dnssecChainSerialised),
    );
    expect(Buffer.from(AsnSerializer.serialize(bundle.organisationCertificate))).toStrictEqual(
      Buffer.from(orgCertificate),
    );
    expect(Buffer.from(AsnSerializer.serialize(bundle.memberCertificate))).toStrictEqual(
      Buffer.from(memberCertificate),
    );
  });
});
