import { jest } from '@jest/globals';
import { AsnParser, AsnSerializer } from '@peculiar/asn1-schema';
import { Certificate as CertificateSchema } from '@peculiar/asn1-x509';
import { subSeconds, setMilliseconds } from 'date-fns';
import type { OctetString } from 'asn1js';
import {
  Attribute,
  type ContentInfo,
  SignedData as SignedDataSchema,
  EncapsulatedContent,
  type SignerInfo,
} from '@peculiar/asn1-cms';

import { generateMemberIdFixture } from '../../testUtils/veraStubs/memberIdFixture.js';
import {
  ORG_NAME,
  ORG_DOMAIN,
  ORG_KEY_PAIR,
  ORG_KEY_SPEC,
} from '../../testUtils/veraStubs/organisation.js';
import { DnssecChainSchema } from '../schemas/DnssecChainSchema.js';
import { serialiseMessage } from '../../testUtils/dns.js';
import { arrayBufferFrom } from '../../testUtils/buffers.js';
import { bufferToArray } from '../utils/buffers.js';
import { selfIssueOrganisationCertificate } from '../pki/organisation.js';
import { SERVICE_OID } from '../../testUtils/veraStubs/service.js';
import VeraidError from '../VeraidError.js';
import { DatePeriod } from '../dates.js';
import { VeraidDnssecChain } from '../dns/VeraidDnssecChain.js';
import { generateRsaKeyPair } from '../utils/keys/generation.js';
import { expectErrorToEqual, getPromiseRejection } from '../../testUtils/errors.js';
import CertificateError from '../utils/x509/CertificateError.js';
import { MemberIdBundleSchema } from '../schemas/MemberIdBundleSchema.js';
import Certificate from '../utils/x509/Certificate.js';
import { issueMemberCertificate } from '../pki/member.js';
import { MEMBER_KEY_PAIR, MEMBER_NAME } from '../../testUtils/veraStubs/member.js';
import { SignatureBundleSchema } from '../schemas/SignatureBundleSchema.js';
import { SignedData } from '../utils/cms/SignedData.js';
import { CMS_OIDS, VERAID_OIDS } from '../oids.js';
import { SignatureMetadataSchema } from '../schemas/SignatureMetadataSchema.js';
import { derDeserialize } from '../utils/asn1.js';

import { MemberIdBundle } from './MemberIdBundle.js';
import { serialiseMemberIdBundle } from './serialisation.js';

const { orgCertificateSerialised, memberCertificateSerialised, dnssecChainFixture, datePeriod } =
  await generateMemberIdFixture();
const dnssecChain = new DnssecChainSchema(
  dnssecChainFixture.responses.map(serialiseMessage).map(bufferToArray),
);
const orgCertificateSchema = AsnParser.parse(orgCertificateSerialised, CertificateSchema);
const memberCertificateSchema = AsnParser.parse(memberCertificateSerialised, CertificateSchema);

// Create a plaintext for testing
const PLAINTEXT = arrayBufferFrom('Hello world');

describe('MemberIdBundle', () => {
  describe('serialise', () => {
    test('Version should be 0', () => {
      const bundle = new MemberIdBundle(dnssecChain, orgCertificateSchema, memberCertificateSchema);

      const serialisation = bundle.serialise();

      const bundleDeserialised = AsnParser.parse(serialisation, MemberIdBundleSchema);
      expect(bundleDeserialised.version).toBe(0);
    });

    test('DNSSEC chain should be included', () => {
      const bundle = new MemberIdBundle(dnssecChain, orgCertificateSchema, memberCertificateSchema);

      const serialisation = bundle.serialise();

      const bundleDeserialised = AsnParser.parse(serialisation, MemberIdBundleSchema);
      expect(bundleDeserialised.dnssecChain.map((message) => Buffer.from(message))).toStrictEqual(
        dnssecChain.map((message) => Buffer.from(message)),
      );
    });

    test('Organisation certificate should be included', () => {
      const bundle = new MemberIdBundle(dnssecChain, orgCertificateSchema, memberCertificateSchema);

      const serialisation = bundle.serialise();

      const bundleDeserialised = AsnParser.parse(serialisation, MemberIdBundleSchema);
      expect(bundleDeserialised.organisationCertificate).toStrictEqual(orgCertificateSchema);
    });

    test('Member certificate should be included', () => {
      const bundle = new MemberIdBundle(dnssecChain, orgCertificateSchema, memberCertificateSchema);

      const serialisation = bundle.serialise();

      const bundleDeserialised = AsnParser.parse(serialisation, MemberIdBundleSchema);
      expect(bundleDeserialised.memberCertificate).toStrictEqual(memberCertificateSchema);
    });
  });

  describe('verify', () => {
    describe('Certificate chain', () => {
      test('Member certificate should be issued by organisation certificate', async () => {
        const otherOrgCertSerialised = await selfIssueOrganisationCertificate(
          ORG_NAME,
          await generateRsaKeyPair(),
          datePeriod.end,
          { startDate: datePeriod.start },
        );
        const bundle = new MemberIdBundle(
          dnssecChain,
          AsnParser.parse(otherOrgCertSerialised, CertificateSchema),
          memberCertificateSchema,
        );

        const error = await getPromiseRejection(
          async () => bundle.verify(SERVICE_OID, datePeriod),
          VeraidError,
        );

        expectErrorToEqual(
          error,
          new VeraidError('Member certificate was not issued by organisation', {
            cause: expect.any(CertificateError),
          }),
        );
      });

      test('Certificates should overlap with specified period', async () => {
        const bundle = new MemberIdBundle(
          dnssecChain,
          orgCertificateSchema,
          memberCertificateSchema,
        );
        const pastPeriod = DatePeriod.init(
          subSeconds(datePeriod.start, 2),
          subSeconds(datePeriod.start, 1),
        );

        await expect(async () => bundle.verify(SERVICE_OID, pastPeriod)).rejects.toThrowWithMessage(
          VeraidError,
          `Validity period of certificate chain (${datePeriod.toString()}) ` +
            `does not overlap with required period (${pastPeriod.toString()})`,
        );
      });
    });

    describe('User name validation', () => {
      const errorMessage =
        'User name should not contain at signs or whitespace other than simple spaces';
      const orgCertificate = Certificate.deserialize(orgCertificateSerialised);

      async function issueInvalidMemberCertificate(userName: string): Promise<CertificateSchema> {
        const certificate = await Certificate.issue({
          commonName: userName,
          subjectPublicKey: MEMBER_KEY_PAIR.publicKey,
          issuerCertificate: orgCertificate,
          issuerPrivateKey: ORG_KEY_PAIR.privateKey,
          validityEndDate: datePeriod.end,
          validityStartDate: datePeriod.start,
        });
        const serialisation = certificate.serialize();
        return AsnParser.parse(serialisation, CertificateSchema);
      }

      test('should not contain at signs', async () => {
        const invalidMemberCertificate = await issueInvalidMemberCertificate(`@${MEMBER_NAME}`);
        const bundle = new MemberIdBundle(
          dnssecChain,
          orgCertificateSchema,
          invalidMemberCertificate,
        );

        await expect(async () =>
          bundle.verify(SERVICE_OID, datePeriod, dnssecChainFixture.trustAnchors),
        ).rejects.toThrowWithMessage(VeraidError, errorMessage);
      });

      test('should not contain tabs', async () => {
        const invalidMemberCertificate = await issueInvalidMemberCertificate(`\t${MEMBER_NAME}`);
        const bundle = new MemberIdBundle(
          dnssecChain,
          orgCertificateSchema,
          invalidMemberCertificate,
        );

        await expect(async () =>
          bundle.verify(SERVICE_OID, datePeriod, dnssecChainFixture.trustAnchors),
        ).rejects.toThrowWithMessage(VeraidError, errorMessage);
      });

      test('should not contain carriage returns', async () => {
        const invalidMemberCertificate = await issueInvalidMemberCertificate(`\r${MEMBER_NAME}`);
        const bundle = new MemberIdBundle(
          dnssecChain,
          orgCertificateSchema,
          invalidMemberCertificate,
        );

        await expect(async () =>
          bundle.verify(SERVICE_OID, datePeriod, dnssecChainFixture.trustAnchors),
        ).rejects.toThrowWithMessage(VeraidError, errorMessage);
      });

      test('should not contain line feeds', async () => {
        const invalidMemberCertificate = await issueInvalidMemberCertificate(`\n${MEMBER_NAME}`);
        const bundle = new MemberIdBundle(
          dnssecChain,
          orgCertificateSchema,
          invalidMemberCertificate,
        );

        await expect(async () =>
          bundle.verify(SERVICE_OID, datePeriod, dnssecChainFixture.trustAnchors),
        ).rejects.toThrowWithMessage(VeraidError, errorMessage);
      });
    });

    describe('DNSSEC chain', () => {
      test('Service OID should be verified', async () => {
        const bundle = new MemberIdBundle(
          dnssecChain,
          orgCertificateSchema,
          memberCertificateSchema,
        );
        const chainVerificationSpy = jest.spyOn(VeraidDnssecChain.prototype, 'verify');

        await bundle.verify(SERVICE_OID, datePeriod, dnssecChainFixture.trustAnchors);

        expect(chainVerificationSpy).toHaveBeenCalledWith(
          expect.anything(),
          SERVICE_OID,
          expect.anything(),
          expect.anything(),
        );
      });

      test('Key spec should match that set in TXT rdata', async () => {
        const bundle = new MemberIdBundle(
          dnssecChain,
          orgCertificateSchema,
          memberCertificateSchema,
        );
        const chainVerificationSpy = jest.spyOn(VeraidDnssecChain.prototype, 'verify');

        await bundle.verify(SERVICE_OID, datePeriod, dnssecChainFixture.trustAnchors);

        expect(chainVerificationSpy).toHaveBeenCalledWith(
          ORG_KEY_SPEC,
          expect.anything(),
          expect.anything(),
          expect.anything(),
        );
      });

      test('Date period should be intersection of specified one and the certificates', async () => {
        const bundle = new MemberIdBundle(
          dnssecChain,
          orgCertificateSchema,
          memberCertificateSchema,
        );
        const chainVerificationSpy = jest.spyOn(VeraidDnssecChain.prototype, 'verify');
        const narrowPeriod = DatePeriod.init(
          subSeconds(datePeriod.start, 1),
          subSeconds(datePeriod.end, 1),
        );

        await bundle.verify(SERVICE_OID, narrowPeriod, dnssecChainFixture.trustAnchors);

        const intersection = datePeriod.intersect(narrowPeriod)!;
        expect(chainVerificationSpy).toHaveBeenCalledWith(
          expect.anything(),
          expect.anything(),
          intersection,
          expect.anything(),
        );
      });

      test('Verification errors should be propagated', async () => {
        const bundle = new MemberIdBundle(
          dnssecChain,
          orgCertificateSchema,
          memberCertificateSchema,
        );

        // Do not pass trusted anchors
        await expect(async () => bundle.verify(SERVICE_OID, datePeriod)).rejects.toThrowWithMessage(
          VeraidError,
          /^VeraId DNSSEC chain is BOGUS/u,
        );
      });
    });

    describe('Valid result', () => {
      test('Organisation name should be output', async () => {
        const bundle = new MemberIdBundle(
          dnssecChain,
          orgCertificateSchema,
          memberCertificateSchema,
        );

        const { organisation } = await bundle.verify(
          SERVICE_OID,
          datePeriod,
          dnssecChainFixture.trustAnchors,
        );

        expect(organisation).toStrictEqual(ORG_NAME);
      });

      test('Trailing dot should be removed from domain if present', async () => {
        const otherOrgCertificateSerialised = await selfIssueOrganisationCertificate(
          ORG_DOMAIN,
          ORG_KEY_PAIR,
          datePeriod.end,
          { startDate: datePeriod.start },
        );
        const fixture = await generateMemberIdFixture({
          datePeriod,
          orgCertificateSerialised: otherOrgCertificateSerialised,
        });
        expect(Certificate.deserialize(otherOrgCertificateSerialised).commonName).toEndWith('.');
        const bundle = new MemberIdBundle(
          dnssecChain,
          AsnParser.parse(otherOrgCertificateSerialised, CertificateSchema),
          AsnParser.parse(fixture.memberCertificateSerialised, CertificateSchema),
        );

        const { organisation } = await bundle.verify(
          SERVICE_OID,
          datePeriod,
          fixture.dnssecChainFixture.trustAnchors,
        );

        expect(organisation).toStrictEqual(ORG_NAME);
        expect(organisation).not.toEndWith('.');
      });

      test('User name should be output if member is a user', async () => {
        const bundle = new MemberIdBundle(
          dnssecChain,
          orgCertificateSchema,
          memberCertificateSchema,
        );

        const { user } = await bundle.verify(
          SERVICE_OID,
          datePeriod,
          dnssecChainFixture.trustAnchors,
        );

        expect(user).toStrictEqual(MEMBER_NAME);
      });

      test('User name should not be output if member is a bot', async () => {
        const botCertificateSerialised = await issueMemberCertificate(
          undefined,
          MEMBER_KEY_PAIR.publicKey,
          orgCertificateSerialised,
          ORG_KEY_PAIR.privateKey,
          datePeriod.end,
          { startDate: datePeriod.start },
        );
        const bundle = new MemberIdBundle(
          dnssecChain,
          orgCertificateSchema,
          AsnParser.parse(botCertificateSerialised, CertificateSchema),
        );

        const { user } = await bundle.verify(
          SERVICE_OID,
          datePeriod,
          dnssecChainFixture.trustAnchors,
        );

        expect(user).toBeUndefined();
      });
    });
  });

  describe('sign', () => {
    test('Version should be 0', async () => {
      const bundle = new MemberIdBundle(dnssecChain, orgCertificateSchema, memberCertificateSchema);

      const signatureSerialised = await bundle.sign(
        PLAINTEXT,
        SERVICE_OID,
        MEMBER_KEY_PAIR.privateKey,
        datePeriod.end,
      );

      const { version } = AsnParser.parse(signatureSerialised, SignatureBundleSchema);
      expect(version).toBe(0);
    });

    test('DNSSEC chain should be attached', async () => {
      const bundle = new MemberIdBundle(dnssecChain, orgCertificateSchema, memberCertificateSchema);

      const signatureSerialised = await bundle.sign(
        PLAINTEXT,
        SERVICE_OID,
        MEMBER_KEY_PAIR.privateKey,
        datePeriod.end,
      );

      const { dnssecChain: signatureDnssecChain } = AsnParser.parse(
        signatureSerialised,
        SignatureBundleSchema,
      );
      expect(Buffer.from(AsnSerializer.serialize(signatureDnssecChain))).toStrictEqual(
        Buffer.from(AsnSerializer.serialize(dnssecChain)),
      );
    });

    test('Organisation certificate should be attached', async () => {
      const bundle = new MemberIdBundle(dnssecChain, orgCertificateSchema, memberCertificateSchema);

      const signatureSerialised = await bundle.sign(
        PLAINTEXT,
        SERVICE_OID,
        MEMBER_KEY_PAIR.privateKey,
        datePeriod.end,
      );

      const { organisationCertificate } = AsnParser.parse(
        signatureSerialised,
        SignatureBundleSchema,
      );
      expect(Buffer.from(AsnSerializer.serialize(organisationCertificate))).toStrictEqual(
        Buffer.from(orgCertificateSerialised),
      );
    });

    describe('Signature', () => {
      function getSignedData(contentInfo: ContentInfo) {
        expect(contentInfo.contentType).toStrictEqual(CMS_OIDS.SIGNED_DATA);
        return AsnParser.parse(contentInfo.content, SignedDataSchema);
      }

      test('Plaintext should be signed with specified private key', async () => {
        const bundle = new MemberIdBundle(
          dnssecChain,
          orgCertificateSchema,
          memberCertificateSchema,
        );

        const signatureSerialised = await bundle.sign(
          PLAINTEXT,
          SERVICE_OID,
          MEMBER_KEY_PAIR.privateKey,
          datePeriod.end,
        );

        const { signature } = AsnParser.parse(signatureSerialised, SignatureBundleSchema);
        const signedData = SignedData.deserialize(AsnSerializer.serialize(signature));
        await signedData.verify(PLAINTEXT);
        const memberCertificate = Certificate.deserialize(memberCertificateSerialised);
        expect(signedData.signerCertificate!.isEqual(memberCertificate)).toBeTrue();
      });

      test('Member certificate should be attached', async () => {
        const bundle = new MemberIdBundle(
          dnssecChain,
          orgCertificateSchema,
          memberCertificateSchema,
        );

        const signatureSerialised = await bundle.sign(
          PLAINTEXT,
          SERVICE_OID,
          MEMBER_KEY_PAIR.privateKey,
          datePeriod.end,
        );

        const { signature } = AsnParser.parse(signatureSerialised, SignatureBundleSchema);
        const { certificates } = getSignedData(signature);
        const attachedCertsSerialised = certificates!.map((cert) =>
          Buffer.from(AsnSerializer.serialize(cert)),
        );
        expect(attachedCertsSerialised).toContainEqual(Buffer.from(memberCertificateSerialised));
      });

      test('Plaintext should be detached by default', async () => {
        const bundle = new MemberIdBundle(
          dnssecChain,
          orgCertificateSchema,
          memberCertificateSchema,
        );

        const signatureSerialised = await bundle.sign(
          PLAINTEXT,
          SERVICE_OID,
          MEMBER_KEY_PAIR.privateKey,
          datePeriod.end,
        );

        const { signature } = AsnParser.parse(signatureSerialised, SignatureBundleSchema);
        const { encapContentInfo } = getSignedData(signature);
        expect(encapContentInfo.eContent).toBeUndefined();
      });

      test('Plaintext should be attached if requested', async () => {
        const bundle = new MemberIdBundle(
          dnssecChain,
          orgCertificateSchema,
          memberCertificateSchema,
        );

        const signatureSerialised = await bundle.sign(
          PLAINTEXT,
          SERVICE_OID,
          MEMBER_KEY_PAIR.privateKey,
          datePeriod.end,
          { shouldEncapsulatePlaintext: true },
        );

        const { signature } = AsnParser.parse(signatureSerialised, SignatureBundleSchema);
        const { encapContentInfo } = getSignedData(signature);
        expect(encapContentInfo.eContent).toBeInstanceOf(EncapsulatedContent);
        const encapsulatedContentSerialised = encapContentInfo.eContent!.any!;
        const encapsulatedContentAsn1 = derDeserialize(
          encapsulatedContentSerialised,
        ) as OctetString;
        expect(new Uint8Array(encapsulatedContentAsn1.getValue())).toStrictEqual(
          new Uint8Array(PLAINTEXT),
        );
      });

      describe('Metadata', () => {
        function getSignedAttribute(signerInfo: SignerInfo, attributeOid: string) {
          const matchingAttribute = signerInfo.signedAttrs!.find(
            (attribute) => attribute.attrType === attributeOid,
          );
          expect(matchingAttribute).toBeInstanceOf(Attribute);
          return matchingAttribute!.attrValues;
        }

        function getSignatureMetadata(signature: ContentInfo) {
          const { signerInfos } = getSignedData(signature);
          const attributeValues = getSignedAttribute(
            signerInfos[0],
            VERAID_OIDS.SIGNATURE_METADATA_ATTR,
          );
          expect(attributeValues).toHaveLength(1);
          return AsnParser.parse(attributeValues[0], SignatureMetadataSchema);
        }

        test('Service OID should be attached', async () => {
          const bundle = new MemberIdBundle(
            dnssecChain,
            orgCertificateSchema,
            memberCertificateSchema,
          );

          const signatureSerialised = await bundle.sign(
            PLAINTEXT,
            SERVICE_OID,
            MEMBER_KEY_PAIR.privateKey,
            datePeriod.end,
          );

          const { signature } = AsnParser.parse(signatureSerialised, SignatureBundleSchema);
          const { serviceOid } = getSignatureMetadata(signature);
          expect(serviceOid).toStrictEqual(SERVICE_OID);
        });

        test('Expiry date should be attached', async () => {
          const bundle = new MemberIdBundle(
            dnssecChain,
            orgCertificateSchema,
            memberCertificateSchema,
          );

          const signatureSerialised = await bundle.sign(
            PLAINTEXT,
            SERVICE_OID,
            MEMBER_KEY_PAIR.privateKey,
            datePeriod.end,
          );

          const { signature } = AsnParser.parse(signatureSerialised, SignatureBundleSchema);
          const { validityPeriod } = getSignatureMetadata(signature);
          expect(validityPeriod.end).toStrictEqual(datePeriod.end);
        });

        test('Start date should default to the current time', async () => {
          const beforeSignatureDate = setMilliseconds(new Date(), 0);
          const bundle = new MemberIdBundle(
            dnssecChain,
            orgCertificateSchema,
            memberCertificateSchema,
          );

          const signatureSerialised = await bundle.sign(
            PLAINTEXT,
            SERVICE_OID,
            MEMBER_KEY_PAIR.privateKey,
            datePeriod.end,
          );
          const afterSignatureDate = new Date();

          const { signature } = AsnParser.parse(signatureSerialised, SignatureBundleSchema);
          const { validityPeriod } = getSignatureMetadata(signature);
          expect(validityPeriod.start).toBeBetween(beforeSignatureDate, afterSignatureDate);
        });

        test('Any explicit start date should be honoured', async () => {
          const startDate = subSeconds(datePeriod.start, 1);
          const bundle = new MemberIdBundle(
            dnssecChain,
            orgCertificateSchema,
            memberCertificateSchema,
          );

          const signatureSerialised = await bundle.sign(
            PLAINTEXT,
            SERVICE_OID,
            MEMBER_KEY_PAIR.privateKey,
            datePeriod.end,
            { startDate },
          );

          const { signature } = AsnParser.parse(signatureSerialised, SignatureBundleSchema);
          const { validityPeriod } = getSignatureMetadata(signature);
          expect(validityPeriod.start).toStrictEqual(startDate);
        });

        test('Start date after expiry date should be refused', async () => {
          const invalidExpiryDate = subSeconds(datePeriod.start, 1);
          const bundle = new MemberIdBundle(
            dnssecChain,
            orgCertificateSchema,
            memberCertificateSchema,
          );

          await expect(async () =>
            bundle.sign(PLAINTEXT, SERVICE_OID, MEMBER_KEY_PAIR.privateKey, invalidExpiryDate, {
              startDate: datePeriod.start,
            }),
          ).rejects.toThrowWithMessage(
            VeraidError,
            'Signature start date cannot be after expiry date',
          );
        });
      });
    });
  });
});

describe('deserialise', () => {
  test('Malformed member Id bundle should be refused', () => {
    const malformedBundle = arrayBufferFrom('malformed');

    expect(() => MemberIdBundle.deserialise(malformedBundle)).toThrowWithMessage(
      VeraidError,
      'Member id bundle is malformed',
    );
  });

  test('Should create a MemberIdBundle instance from serialized data', async () => {
    const fixture = await generateMemberIdFixture();
    const fixtureOrgCertSerialised = fixture.orgCertificateSerialised;
    const fixtureMemberCertSerialised = fixture.memberCertificateSerialised;
    const fixtureDnssecChain = fixture.dnssecChainFixture;

    const dnssecChainSerialised = AsnSerializer.serialize(
      new DnssecChainSchema(fixtureDnssecChain.responses.map(serialiseMessage).map(bufferToArray)),
    );

    const memberIdBundle = serialiseMemberIdBundle(
      fixtureMemberCertSerialised,
      fixtureOrgCertSerialised,
      dnssecChainSerialised,
    );

    const bundle = MemberIdBundle.deserialise(memberIdBundle);

    expect(bundle).toBeInstanceOf(MemberIdBundle);
    expect(Buffer.from(bundle.serialise())).toStrictEqual(Buffer.from(memberIdBundle));
  });
});
