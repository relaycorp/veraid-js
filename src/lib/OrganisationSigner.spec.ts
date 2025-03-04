import { AsnParser } from '@peculiar/asn1-schema';
import { Certificate as CertificateSchema } from '@peculiar/asn1-x509';

import { generateMemberIdFixture } from '../testUtils/veraStubs/memberIdFixture.js';
import { MEMBER_NAME } from '../testUtils/veraStubs/member.js';
import { serialiseMessage } from '../testUtils/dns.js';

import { bufferToArray } from './utils/buffers.js';
import { DnssecChainSchema } from './schemas/DnssecChainSchema.js';
import { OrganisationSigner } from './OrganisationSigner.js';

describe('OrganisationSigner', () => {
  let dnssecChain: DnssecChainSchema;
  let orgCertificateSchema: CertificateSchema;

  beforeAll(async () => {
    const { orgCertificateSerialised, dnssecChainFixture } = await generateMemberIdFixture();
    dnssecChain = new DnssecChainSchema(
      dnssecChainFixture.responses.map(serialiseMessage).map(bufferToArray),
    );
    orgCertificateSchema = AsnParser.parse(orgCertificateSerialised, CertificateSchema);
  });

  describe('signerCertificateSchema', () => {
    test('should return undefined', () => {
      const signer = new OrganisationSigner(dnssecChain, orgCertificateSchema);

      const { signerCertificateSchema } = signer;

      expect(signerCertificateSchema).toBeUndefined();
    });
  });

  describe('signerName', () => {
    test('should return undefined if attributedMemberName is not provided', () => {
      const signer = new OrganisationSigner(dnssecChain, orgCertificateSchema);

      const { signerName } = signer;

      expect(signerName).toBeUndefined();
    });

    test('should return attributedMemberName if provided', () => {
      const signer = new OrganisationSigner(dnssecChain, orgCertificateSchema, MEMBER_NAME);

      const { signerName } = signer;

      expect(signerName).toBe(MEMBER_NAME);
    });
  });
});
