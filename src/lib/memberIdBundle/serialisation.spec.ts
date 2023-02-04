import { AsnParser, AsnSerializer } from '@peculiar/asn1-schema';

import { arrayBufferFrom } from '../../testUtils/buffers.js';
import { DnssecChainSchema } from '../schemas/DnssecChainSchema.js';
import VeraError from '../VeraError.js';
import { generateMemberIdFixture } from '../../testUtils/veraStubs/memberIdFixture.js';
import { serialiseMessage } from '../../testUtils/dns.js';
import { bufferToArray } from '../utils/buffers.js';
import { MemberIdBundleSchema } from '../schemas/MemberIdBundleSchema.js';

import { serialiseMemberIdBundle } from './serialisation.js';

const { orgCertificateSerialised, memberCertificateSerialised, dnssecChainFixture } =
  await generateMemberIdFixture();

const dnssecChain = new DnssecChainSchema(
  dnssecChainFixture.responses.map(serialiseMessage).map(bufferToArray),
);
const dnssecChainSerialised = AsnSerializer.serialize(dnssecChain);

describe('serialiseMemberIdBundle', () => {
  test('Malformed member certificate should be refused', () => {
    expect(() =>
      serialiseMemberIdBundle(
        arrayBufferFrom('malformed'),
        orgCertificateSerialised,
        dnssecChainSerialised,
      ),
    ).toThrowWithMessage(VeraError, 'Member certificate is malformed');
  });

  test('Malformed organisation certificate should be refused', () => {
    expect(() =>
      serialiseMemberIdBundle(
        memberCertificateSerialised,
        arrayBufferFrom('malformed'),
        dnssecChainSerialised,
      ),
    ).toThrowWithMessage(VeraError, 'Organisation certificate is malformed');
  });

  test('Malformed DNSSEC chain should be refused', () => {
    expect(() =>
      serialiseMemberIdBundle(
        memberCertificateSerialised,
        orgCertificateSerialised,
        arrayBufferFrom('malformed'),
      ),
    ).toThrowWithMessage(VeraError, 'DNSSEC chain is malformed');
  });

  test('Well-formed bundle should be output', () => {
    const bundleSerialised = serialiseMemberIdBundle(
      memberCertificateSerialised,
      orgCertificateSerialised,
      dnssecChainSerialised,
    );

    const bundle = AsnParser.parse(bundleSerialised, MemberIdBundleSchema);
    expect(Buffer.from(AsnSerializer.serialize(bundle.dnssecChain))).toStrictEqual(
      Buffer.from(dnssecChainSerialised),
    );
    expect(Buffer.from(AsnSerializer.serialize(bundle.organisationCertificate))).toStrictEqual(
      Buffer.from(orgCertificateSerialised),
    );
    expect(Buffer.from(AsnSerializer.serialize(bundle.memberCertificate))).toStrictEqual(
      Buffer.from(memberCertificateSerialised),
    );
  });
});
