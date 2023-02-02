import { AsnParser, AsnSerializer } from '@peculiar/asn1-schema';

import { arrayBufferFrom } from '../../testUtils/buffers.js';
import { DnssecChainSchema } from '../dns/DnssecChainSchema.js';
import VeraError from '../VeraError.js';
import { generateMemberIdFixture } from '../../testUtils/veraStubs/memberIdFixture.js';
import { serialiseMessage } from '../../testUtils/dns.js';
import { bufferToArray } from '../utils/buffers.js';

import { serialiseMemberIdBundle } from './serialisation.js';
import { MemberIdBundleSchema } from './MemberIdBundleSchema.js';

const { organisationCertificate, memberCertificate, veraDnssecChain } =
  await generateMemberIdFixture();

const dnssecChain = new DnssecChainSchema(
  veraDnssecChain.responses.map(serialiseMessage).map(bufferToArray),
);
const dnssecChainSerialised = AsnSerializer.serialize(dnssecChain);

describe('serialiseMemberIdBundle', () => {
  test('Malformed member certificate should be refused', () => {
    expect(() =>
      serialiseMemberIdBundle(
        arrayBufferFrom('malformed'),
        organisationCertificate,
        dnssecChainSerialised,
      ),
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
      serialiseMemberIdBundle(
        memberCertificate,
        organisationCertificate,
        arrayBufferFrom('malformed'),
      ),
    ).toThrowWithMessage(VeraError, 'DNSSEC chain is malformed');
  });

  test('Well-formed bundle should be output', () => {
    const bundleSerialised = serialiseMemberIdBundle(
      memberCertificate,
      organisationCertificate,
      dnssecChainSerialised,
    );

    const bundle = AsnParser.parse(bundleSerialised, MemberIdBundleSchema);
    expect(Buffer.from(AsnSerializer.serialize(bundle.dnssecChain))).toStrictEqual(
      Buffer.from(dnssecChainSerialised),
    );
    expect(Buffer.from(AsnSerializer.serialize(bundle.organisationCertificate))).toStrictEqual(
      Buffer.from(organisationCertificate),
    );
    expect(Buffer.from(AsnSerializer.serialize(bundle.memberCertificate))).toStrictEqual(
      Buffer.from(memberCertificate),
    );
  });
});
