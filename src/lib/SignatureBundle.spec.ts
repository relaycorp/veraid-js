/* eslint-disable max-lines */
import { AsnParser, AsnSerializer } from '@peculiar/asn1-schema';
import { Certificate as CertificateSchema } from '@peculiar/asn1-x509';
import { subSeconds, setMilliseconds } from 'date-fns';
import { type OctetString, Null } from 'asn1js';
import {
  Attribute,
  ContentInfo,
  SignedData as SignedDataSchema,
  EncapsulatedContent,
  type SignerInfo,
} from '@peculiar/asn1-cms';
import { jest } from '@jest/globals';
import { type Message, RrSet, SecurityStatus } from '@relaycorp/dnssec';
import { Attribute as PkijsAttribute } from 'pkijs';

import { generateMemberIdFixture } from '../testUtils/veraStubs/memberIdFixture.js';
import { serialiseMessage } from '../testUtils/dns.js';
import { arrayBufferFrom } from '../testUtils/buffers.js';
import { SERVICE_OID } from '../testUtils/veraStubs/service.js';
import { MEMBER_KEY_PAIR, MEMBER_NAME } from '../testUtils/veraStubs/member.js';
import {
  ORG_KEY_PAIR,
  ORG_NAME,
  VERAID_RECORD,
  VERAID_RECORD_TTL_OVERRIDE,
} from '../testUtils/veraStubs/organisation.js';
import { expectErrorToEqual, getPromiseRejection } from '../testUtils/errors.js';
import { MOCK_CHAIN } from '../testUtils/veraStubs/dnssec.js';

import { DnssecChainSchema } from './schemas/DnssecChainSchema.js';
import { bufferToArray } from './utils/buffers.js';
import VeraidError from './VeraidError.js';
import Certificate from './utils/x509/Certificate.js';
import { SignatureBundleSchema } from './schemas/SignatureBundleSchema.js';
import { SignedData } from './utils/cms/SignedData.js';
import { CMS_OIDS, VERAID_OIDS } from './oids.js';
import { SignatureMetadataSchema } from './schemas/SignatureMetadataSchema.js';
import { derDeserialize } from './utils/asn1.js';
import { MemberIdBundle } from './memberIdBundle/MemberIdBundle.js';
import { SignatureBundle } from './SignatureBundle.js';
import CmsError from './utils/cms/CmsError.js';
import { serialiseMemberIdBundle } from './memberIdBundle/serialisation.js';
import { DatePeriod, type IDatePeriod } from './dates.js';
import { issueMemberCertificate } from './pki/member.js';
import { DatePeriodSchema } from './schemas/DatePeriodSchema.js';
import { generateTxtRdata } from './dns/rdataSerialisation.js';

const { orgCertificateSerialised, memberCertificateSerialised, dnssecChainFixture, datePeriod } =
  await generateMemberIdFixture();
const dnssecChain = new DnssecChainSchema(
  dnssecChainFixture.responses.map(serialiseMessage).map(bufferToArray),
);

const orgCertificateSchema = AsnParser.parse(orgCertificateSerialised, CertificateSchema);
const memberCertificateSchema = AsnParser.parse(memberCertificateSerialised, CertificateSchema);

const PLAINTEXT = arrayBufferFrom('Hello world');

const VERIFY_PLAINTEXT = arrayBufferFrom('the plaintext');

const DNSSEC_CHAIN_SERIALISED = AsnSerializer.serialize(
  new DnssecChainSchema(dnssecChainFixture.responses.map(serialiseMessage).map(bufferToArray)),
);
const MEMBER_ID_BUNDLE = serialiseMemberIdBundle(
  memberCertificateSerialised,
  orgCertificateSerialised,
  DNSSEC_CHAIN_SERIALISED,
);

const bundleInstance = MemberIdBundle.deserialise(MEMBER_ID_BUNDLE);
const verifySignatureBundle = await SignatureBundle.sign(
  VERIFY_PLAINTEXT,
  SERVICE_OID,
  bundleInstance,
  MEMBER_KEY_PAIR.privateKey,
  datePeriod.end,
  { startDate: datePeriod.start },
);
const SIGNATURE_BUNDLE_SERIALISED = verifySignatureBundle.serialise();

describe('SignatureBundle', () => {
  describe('sign', () => {
    test('Version should be 0', async () => {
      const memberIdBundle = new MemberIdBundle(
        dnssecChain,
        orgCertificateSchema,
        memberCertificateSchema,
      );

      const signatureBundle = await SignatureBundle.sign(
        PLAINTEXT,
        SERVICE_OID,
        memberIdBundle,
        MEMBER_KEY_PAIR.privateKey,
        datePeriod.end,
      );

      const signatureSerialised = signatureBundle.serialise();
      const { version } = AsnParser.parse(signatureSerialised, SignatureBundleSchema);
      expect(version).toBe(0);
    });

    test('DNSSEC chain should be attached', async () => {
      const memberIdBundle = new MemberIdBundle(
        dnssecChain,
        orgCertificateSchema,
        memberCertificateSchema,
      );

      const signatureBundle = await SignatureBundle.sign(
        PLAINTEXT,
        SERVICE_OID,
        memberIdBundle,
        MEMBER_KEY_PAIR.privateKey,
        datePeriod.end,
      );

      const signatureSerialised = signatureBundle.serialise();
      const { dnssecChain: signatureDnssecChain } = AsnParser.parse(
        signatureSerialised,
        SignatureBundleSchema,
      );
      expect(Buffer.from(AsnSerializer.serialize(signatureDnssecChain))).toStrictEqual(
        Buffer.from(AsnSerializer.serialize(dnssecChain)),
      );
    });

    test('Organisation certificate should be attached', async () => {
      const memberIdBundle = new MemberIdBundle(
        dnssecChain,
        orgCertificateSchema,
        memberCertificateSchema,
      );

      const signatureBundle = await SignatureBundle.sign(
        PLAINTEXT,
        SERVICE_OID,
        memberIdBundle,
        MEMBER_KEY_PAIR.privateKey,
        datePeriod.end,
      );

      const signatureSerialised = signatureBundle.serialise();
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
        const memberIdBundle = new MemberIdBundle(
          dnssecChain,
          orgCertificateSchema,
          memberCertificateSchema,
        );

        const signatureBundle = await SignatureBundle.sign(
          PLAINTEXT,
          SERVICE_OID,
          memberIdBundle,
          MEMBER_KEY_PAIR.privateKey,
          datePeriod.end,
        );

        const signatureSerialised = signatureBundle.serialise();
        const { signature } = AsnParser.parse(signatureSerialised, SignatureBundleSchema);
        const signedData = SignedData.deserialize(AsnSerializer.serialize(signature));
        await signedData.verify(PLAINTEXT);
        const memberCertificate = Certificate.deserialize(memberCertificateSerialised);
        expect(signedData.signerCertificate!.isEqual(memberCertificate)).toBeTrue();
      });

      test('Member certificate should be attached', async () => {
        const memberIdBundle = new MemberIdBundle(
          dnssecChain,
          orgCertificateSchema,
          memberCertificateSchema,
        );

        const signatureBundle = await SignatureBundle.sign(
          PLAINTEXT,
          SERVICE_OID,
          memberIdBundle,
          MEMBER_KEY_PAIR.privateKey,
          datePeriod.end,
        );

        const signatureSerialised = signatureBundle.serialise();
        const { signature } = AsnParser.parse(signatureSerialised, SignatureBundleSchema);
        const { certificates } = getSignedData(signature);
        const attachedCertsSerialised = certificates!.map((cert) =>
          Buffer.from(AsnSerializer.serialize(cert)),
        );
        expect(attachedCertsSerialised).toContainEqual(Buffer.from(memberCertificateSerialised));
      });

      test('Plaintext should be detached by default', async () => {
        const memberIdBundle = new MemberIdBundle(
          dnssecChain,
          orgCertificateSchema,
          memberCertificateSchema,
        );

        const signatureBundle = await SignatureBundle.sign(
          PLAINTEXT,
          SERVICE_OID,
          memberIdBundle,
          MEMBER_KEY_PAIR.privateKey,
          datePeriod.end,
        );

        const signatureSerialised = signatureBundle.serialise();
        const { signature } = AsnParser.parse(signatureSerialised, SignatureBundleSchema);
        const { encapContentInfo } = getSignedData(signature);
        expect(encapContentInfo.eContent).toBeUndefined();
      });

      test('Plaintext should be attached if requested', async () => {
        const memberIdBundle = new MemberIdBundle(
          dnssecChain,
          orgCertificateSchema,
          memberCertificateSchema,
        );

        const signatureBundle = await SignatureBundle.sign(
          PLAINTEXT,
          SERVICE_OID,
          memberIdBundle,
          MEMBER_KEY_PAIR.privateKey,
          datePeriod.end,
          { shouldEncapsulatePlaintext: true },
        );

        const signatureSerialised = signatureBundle.serialise();
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
          const memberIdBundle = new MemberIdBundle(
            dnssecChain,
            orgCertificateSchema,
            memberCertificateSchema,
          );

          const signatureBundle = await SignatureBundle.sign(
            PLAINTEXT,
            SERVICE_OID,
            memberIdBundle,
            MEMBER_KEY_PAIR.privateKey,
            datePeriod.end,
          );

          const signatureSerialised = signatureBundle.serialise();
          const { signature } = AsnParser.parse(signatureSerialised, SignatureBundleSchema);
          const { serviceOid } = getSignatureMetadata(signature);
          expect(serviceOid).toStrictEqual(SERVICE_OID);
        });

        test('Expiry date should be attached', async () => {
          const memberIdBundle = new MemberIdBundle(
            dnssecChain,
            orgCertificateSchema,
            memberCertificateSchema,
          );

          const signatureBundle = await SignatureBundle.sign(
            PLAINTEXT,
            SERVICE_OID,
            memberIdBundle,
            MEMBER_KEY_PAIR.privateKey,
            datePeriod.end,
          );

          const signatureSerialised = signatureBundle.serialise();
          const { signature } = AsnParser.parse(signatureSerialised, SignatureBundleSchema);
          const { validityPeriod } = getSignatureMetadata(signature);
          expect(validityPeriod.end).toStrictEqual(datePeriod.end);
        });

        test('Start date should default to the current time', async () => {
          const beforeSignatureDate = setMilliseconds(new Date(), 0);
          const memberIdBundle = new MemberIdBundle(
            dnssecChain,
            orgCertificateSchema,
            memberCertificateSchema,
          );

          const signatureBundle = await SignatureBundle.sign(
            PLAINTEXT,
            SERVICE_OID,
            memberIdBundle,
            MEMBER_KEY_PAIR.privateKey,
            datePeriod.end,
          );
          const afterSignatureDate = new Date();

          const signatureSerialised = signatureBundle.serialise();
          const { signature } = AsnParser.parse(signatureSerialised, SignatureBundleSchema);
          const { validityPeriod } = getSignatureMetadata(signature);
          expect(validityPeriod.start).toBeBetween(beforeSignatureDate, afterSignatureDate);
        });

        test('Any explicit start date should be honoured', async () => {
          const startDate = subSeconds(datePeriod.start, 1);
          const memberIdBundle = new MemberIdBundle(
            dnssecChain,
            orgCertificateSchema,
            memberCertificateSchema,
          );

          const signatureBundle = await SignatureBundle.sign(
            PLAINTEXT,
            SERVICE_OID,
            memberIdBundle,
            MEMBER_KEY_PAIR.privateKey,
            datePeriod.end,
            { startDate },
          );

          const signatureSerialised = signatureBundle.serialise();
          const { signature } = AsnParser.parse(signatureSerialised, SignatureBundleSchema);
          const { validityPeriod } = getSignatureMetadata(signature);
          expect(validityPeriod.start).toStrictEqual(startDate);
        });

        test('Start date after expiry date should be refused', async () => {
          const invalidExpiryDate = subSeconds(datePeriod.start, 1);
          const memberIdBundle = new MemberIdBundle(
            dnssecChain,
            orgCertificateSchema,
            memberCertificateSchema,
          );

          await expect(async () =>
            SignatureBundle.sign(
              PLAINTEXT,
              SERVICE_OID,
              memberIdBundle,
              MEMBER_KEY_PAIR.privateKey,
              invalidExpiryDate,
              { startDate: datePeriod.start },
            ),
          ).rejects.toThrowWithMessage(
            VeraidError,
            'Signature start date cannot be after expiry date',
          );
        });
      });
    });
  });

  describe('serialise', () => {
    test('Version should be 0', async () => {
      const memberIdBundle = new MemberIdBundle(
        dnssecChain,
        orgCertificateSchema,
        memberCertificateSchema,
      );
      const signatureBundle = await SignatureBundle.sign(
        PLAINTEXT,
        SERVICE_OID,
        memberIdBundle,
        MEMBER_KEY_PAIR.privateKey,
        datePeriod.end,
      );

      const serialisation = signatureBundle.serialise();

      const bundleDeserialised = AsnParser.parse(serialisation, SignatureBundleSchema);
      expect(bundleDeserialised.version).toBe(0);
    });

    test('DNSSEC chain should be included', async () => {
      const memberIdBundle = new MemberIdBundle(
        dnssecChain,
        orgCertificateSchema,
        memberCertificateSchema,
      );
      const signatureBundle = await SignatureBundle.sign(
        PLAINTEXT,
        SERVICE_OID,
        memberIdBundle,
        MEMBER_KEY_PAIR.privateKey,
        datePeriod.end,
      );

      const serialisation = signatureBundle.serialise();

      const bundleDeserialised = AsnParser.parse(serialisation, SignatureBundleSchema);
      expect(bundleDeserialised.dnssecChain.map((message) => Buffer.from(message))).toStrictEqual(
        dnssecChain.map((message) => Buffer.from(message)),
      );
    });

    test('Organisation certificate should be included', async () => {
      const memberIdBundle = new MemberIdBundle(
        dnssecChain,
        orgCertificateSchema,
        memberCertificateSchema,
      );
      const signatureBundle = await SignatureBundle.sign(
        PLAINTEXT,
        SERVICE_OID,
        memberIdBundle,
        MEMBER_KEY_PAIR.privateKey,
        datePeriod.end,
      );

      const serialisation = signatureBundle.serialise();

      const bundleDeserialised = AsnParser.parse(serialisation, SignatureBundleSchema);
      expect(bundleDeserialised.organisationCertificate).toStrictEqual(orgCertificateSchema);
    });

    test('Signature should be included', async () => {
      const memberIdBundle = new MemberIdBundle(
        dnssecChain,
        orgCertificateSchema,
        memberCertificateSchema,
      );
      const signatureBundle = await SignatureBundle.sign(
        PLAINTEXT,
        SERVICE_OID,
        memberIdBundle,
        MEMBER_KEY_PAIR.privateKey,
        datePeriod.end,
      );

      const serialisation = signatureBundle.serialise();

      const bundleDeserialised = AsnParser.parse(serialisation, SignatureBundleSchema);
      expect(bundleDeserialised.signature).not.toBeNull();
      expect(bundleDeserialised.signature.contentType).toStrictEqual(CMS_OIDS.SIGNED_DATA);
    });
  });

  describe('deserialise', () => {
    test('Should throw error if version is not 0', async () => {
      const memberIdBundle = new MemberIdBundle(
        dnssecChain,
        orgCertificateSchema,
        memberCertificateSchema,
      );
      const signatureBundle = await SignatureBundle.sign(
        PLAINTEXT,
        SERVICE_OID,
        memberIdBundle,
        MEMBER_KEY_PAIR.privateKey,
        datePeriod.end,
      );
      const serialisation = signatureBundle.serialise();
      const bundleSchema = AsnParser.parse(serialisation, SignatureBundleSchema);
      bundleSchema.version = 1;
      const modifiedSerialisation = AsnSerializer.serialize(bundleSchema);

      expect(() => SignatureBundle.deserialise(modifiedSerialisation)).toThrowWithMessage(
        VeraidError,
        'Unsupported SignatureBundle version',
      );
    });

    test('Should correctly deserialise DNSSEC chain', async () => {
      const memberIdBundle = new MemberIdBundle(
        dnssecChain,
        orgCertificateSchema,
        memberCertificateSchema,
      );
      const signatureBundle = await SignatureBundle.sign(
        PLAINTEXT,
        SERVICE_OID,
        memberIdBundle,
        MEMBER_KEY_PAIR.privateKey,
        datePeriod.end,
      );
      const serialisation = signatureBundle.serialise();

      const deserialisedBundle = SignatureBundle.deserialise(serialisation);

      const { dnssecChainSchema } = deserialisedBundle as unknown as {
        dnssecChainSchema: DnssecChainSchema;
      };
      expect(dnssecChainSchema.map((message) => Buffer.from(message))).toStrictEqual(
        dnssecChain.map((message) => Buffer.from(message)),
      );
    });

    test('Should correctly deserialise organisation certificate', async () => {
      const memberIdBundle = new MemberIdBundle(
        dnssecChain,
        orgCertificateSchema,
        memberCertificateSchema,
      );
      const signatureBundle = await SignatureBundle.sign(
        PLAINTEXT,
        SERVICE_OID,
        memberIdBundle,
        MEMBER_KEY_PAIR.privateKey,
        datePeriod.end,
      );
      const serialisation = signatureBundle.serialise();

      const deserialisedBundle = SignatureBundle.deserialise(serialisation);

      const { orgCertificateSchema: orgCertificate } = deserialisedBundle as unknown as {
        orgCertificateSchema: CertificateSchema;
      };
      expect(Buffer.from(AsnSerializer.serialize(orgCertificate))).toStrictEqual(
        Buffer.from(orgCertificateSerialised),
      );
    });

    test('Should correctly deserialise signature', async () => {
      const memberIdBundle = new MemberIdBundle(
        dnssecChain,
        orgCertificateSchema,
        memberCertificateSchema,
      );
      const signatureBundle = await SignatureBundle.sign(
        PLAINTEXT,
        SERVICE_OID,
        memberIdBundle,
        MEMBER_KEY_PAIR.privateKey,
        datePeriod.end,
      );
      const serialisation = signatureBundle.serialise();

      const deserialisedBundle = SignatureBundle.deserialise(serialisation);

      const { signature } = deserialisedBundle as unknown as { signature: ContentInfo };
      expect(signature.contentType).toStrictEqual(CMS_OIDS.SIGNED_DATA);

      const signedData = SignedData.deserialize(AsnSerializer.serialize(signature));
      await expect(signedData.verify(PLAINTEXT)).resolves.not.toThrow();
    });

    test('Should preserve version 0', async () => {
      const memberIdBundle = new MemberIdBundle(
        dnssecChain,
        orgCertificateSchema,
        memberCertificateSchema,
      );
      const signatureBundle = await SignatureBundle.sign(
        PLAINTEXT,
        SERVICE_OID,
        memberIdBundle,
        MEMBER_KEY_PAIR.privateKey,
        datePeriod.end,
      );
      const serialisation = signatureBundle.serialise();

      const deserialisedBundle = SignatureBundle.deserialise(serialisation);

      const reserialisation = deserialisedBundle.serialise();
      const bundleSchema = AsnParser.parse(reserialisation, SignatureBundleSchema);
      expect(bundleSchema.version).toBe(0);
    });
  });

  describe('verify', () => {
    interface SignatureBundleAttributeSet {
      readonly dnssecResponses: readonly Message[];
      readonly signedData: SignedData;
    }

    function replaceSignatureAttribute(
      signatureBundleSerialised: ArrayBuffer,
      attributes: Partial<SignatureBundleAttributeSet>,
    ): ArrayBuffer {
      const signatureBundleSchema = AsnParser.parse(
        signatureBundleSerialised,
        SignatureBundleSchema,
      );

      if (attributes.dnssecResponses) {
        const responsesSerialised = attributes.dnssecResponses
          .map(serialiseMessage)
          .map(arrayBufferFrom);
        signatureBundleSchema.dnssecChain = new DnssecChainSchema(responsesSerialised);
      }

      if (attributes.signedData) {
        signatureBundleSchema.signature = AsnParser.parse(
          attributes.signedData.serialize(),
          ContentInfo,
        );
      }

      return AsnSerializer.serialize(signatureBundleSchema);
    }

    test('Metadata attribute should be present in signature', async () => {
      const signatureBundleSchema = AsnParser.parse(
        SIGNATURE_BUNDLE_SERIALISED,
        SignatureBundleSchema,
      );
      const memberCertificate = Certificate.deserialize(memberCertificateSerialised);
      const signedData = await SignedData.sign(
        VERIFY_PLAINTEXT,
        MEMBER_KEY_PAIR.privateKey,
        memberCertificate,
        [],
        { shouldEncapsulatePlaintext: false },
      );
      signatureBundleSchema.signature = AsnParser.parse(signedData.serialize(), ContentInfo);
      const signatureBundleSerialised = AsnSerializer.serialize(signatureBundleSchema);
      const bundle = SignatureBundle.deserialise(signatureBundleSerialised);

      await expect(async () =>
        bundle.verify(VERIFY_PLAINTEXT, SERVICE_OID, datePeriod, dnssecChainFixture.trustAnchors),
      ).rejects.toThrowWithMessage(VeraidError, 'Signature metadata is missing');
    });

    test('Metadata attribute should be well-formed', async () => {
      const memberCertificate = Certificate.deserialize(memberCertificateSerialised);
      const attribute = new PkijsAttribute({
        type: VERAID_OIDS.SIGNATURE_METADATA_ATTR,
        values: [new Null()],
      });
      const signedData = await SignedData.sign(
        VERIFY_PLAINTEXT,
        MEMBER_KEY_PAIR.privateKey,
        memberCertificate,
        [],
        {
          shouldEncapsulatePlaintext: false,
          extraSignedAttrs: [attribute],
        },
      );
      const signatureBundleSerialised = replaceSignatureAttribute(SIGNATURE_BUNDLE_SERIALISED, {
        signedData,
      });
      const bundle = SignatureBundle.deserialise(signatureBundleSerialised);

      await expect(async () =>
        bundle.verify(VERIFY_PLAINTEXT, SERVICE_OID, datePeriod, dnssecChainFixture.trustAnchors),
      ).rejects.toThrowWithMessage(VeraidError, 'Signature metadata is malformed');
    });

    test('Metadata should contain valid validity period', async () => {
      const memberCertificate = Certificate.deserialize(memberCertificateSerialised);
      const metadata = new SignatureMetadataSchema();
      metadata.serviceOid = SERVICE_OID;
      metadata.validityPeriod = new DatePeriodSchema();
      metadata.validityPeriod.start = datePeriod.start;
      metadata.validityPeriod.end = subSeconds(datePeriod.start, 1); // Invalid
      const attribute = new PkijsAttribute({
        type: VERAID_OIDS.SIGNATURE_METADATA_ATTR,
        values: [derDeserialize(AsnSerializer.serialize(metadata))],
      });
      const signedData = await SignedData.sign(
        VERIFY_PLAINTEXT,
        MEMBER_KEY_PAIR.privateKey,
        memberCertificate,
        [],
        {
          shouldEncapsulatePlaintext: false,
          extraSignedAttrs: [attribute],
        },
      );
      const signatureBundleSerialised = replaceSignatureAttribute(SIGNATURE_BUNDLE_SERIALISED, {
        signedData,
      });
      const bundle = SignatureBundle.deserialise(signatureBundleSerialised);

      await expect(async () =>
        bundle.verify(VERIFY_PLAINTEXT, SERVICE_OID, datePeriod, dnssecChainFixture.trustAnchors),
      ).rejects.toThrowWithMessage(VeraidError, 'Signature validity period ends before it starts');
    });

    test('Signature should correspond to specified plaintext', async () => {
      const differentPlaintext = bufferToArray(Buffer.from(VERIFY_PLAINTEXT, 1));
      const bundle = SignatureBundle.deserialise(SIGNATURE_BUNDLE_SERIALISED);

      const error = await getPromiseRejection(
        async () =>
          bundle.verify(
            differentPlaintext,
            SERVICE_OID,
            datePeriod,
            dnssecChainFixture.trustAnchors,
          ),
        VeraidError,
      );

      expectErrorToEqual(
        error,
        new VeraidError('Signature is invalid', { cause: expect.any(CmsError) }),
      );
    });

    test('Member id bundle should be valid', async () => {
      const invalidMemberIdBundle = serialiseMemberIdBundle(
        memberCertificateSerialised,
        memberCertificateSerialised, // Invalid
        DNSSEC_CHAIN_SERIALISED,
      );
      const invalidBundle = MemberIdBundle.deserialise(invalidMemberIdBundle);
      const invalidSignatureBundle = await SignatureBundle.sign(
        VERIFY_PLAINTEXT,
        SERVICE_OID,
        invalidBundle,
        MEMBER_KEY_PAIR.privateKey,
        datePeriod.end,
        { startDate: datePeriod.start },
      );
      const signatureBundleSerialised = invalidSignatureBundle.serialise();
      const bundle = SignatureBundle.deserialise(signatureBundleSerialised);

      const error = await getPromiseRejection(
        async () =>
          bundle.verify(VERIFY_PLAINTEXT, SERVICE_OID, datePeriod, dnssecChainFixture.trustAnchors),
        VeraidError,
      );

      expectErrorToEqual(
        error,
        new VeraidError('Member id bundle is invalid', { cause: expect.any(VeraidError) }),
      );
    });

    describe('Service OID', () => {
      test('Service OID should match that of the signature metadata', async () => {
        const differentServiceOid = `${SERVICE_OID}.1`;
        const bundle = SignatureBundle.deserialise(SIGNATURE_BUNDLE_SERIALISED);

        await expect(async () =>
          bundle.verify(
            VERIFY_PLAINTEXT,
            differentServiceOid,
            datePeriod,
            dnssecChainFixture.trustAnchors,
          ),
        ).rejects.toThrowWithMessage(
          VeraidError,
          `Signature is bound to a different service (${SERVICE_OID})`,
        );
      });

      test('Service OID in signature should match that of member id bundle', async () => {
        const bundleVerifySpy = jest.spyOn(MemberIdBundle.prototype, 'verify');
        const differentServiceOid = `${SERVICE_OID}.1`;
        const record = VERAID_RECORD.shallowCopy({
          data: await generateTxtRdata(
            ORG_KEY_PAIR.publicKey,
            VERAID_RECORD_TTL_OVERRIDE,
            differentServiceOid,
          ),
        });
        const { responses: dnssecResponses, trustAnchors } = MOCK_CHAIN.generateFixture(
          RrSet.init(record.makeQuestion(), [record]),
          SecurityStatus.SECURE,
          datePeriod,
        );
        const signatureBundleSerialised = replaceSignatureAttribute(SIGNATURE_BUNDLE_SERIALISED, {
          dnssecResponses,
        });
        const bundle = SignatureBundle.deserialise(signatureBundleSerialised);

        await expect(async () =>
          bundle.verify(VERIFY_PLAINTEXT, SERVICE_OID, datePeriod, trustAnchors),
        ).rejects.toThrowWithMessage(VeraidError, 'Member id bundle is invalid');
        expect(bundleVerifySpy).toHaveBeenCalledWith(
          SERVICE_OID,
          expect.anything(),
          expect.anything(),
        );
      });
    });

    describe('Validity period', () => {
      test('Period should default to the current time', async () => {
        const bundleVerifySpy = jest.spyOn(MemberIdBundle.prototype, 'verify');
        const dateBeforeVerification = new Date();
        const bundle = SignatureBundle.deserialise(SIGNATURE_BUNDLE_SERIALISED);

        await bundle.verify(
          VERIFY_PLAINTEXT,
          SERVICE_OID,
          undefined,
          dnssecChainFixture.trustAnchors,
        );

        const dateAfterVerification = new Date();
        expect(bundleVerifySpy).toHaveBeenCalledWith(
          expect.anything(),
          expect.toSatisfy<DatePeriod>(
            (period) =>
              period.start === period.end &&
              period.start <= dateAfterVerification &&
              dateBeforeVerification <= period.end,
          ),
          expect.anything(),
        );
      });

      test('Period as a single date should be supported', async () => {
        const bundleVerifySpy = jest.spyOn(MemberIdBundle.prototype, 'verify');
        const date = new Date();
        const bundle = SignatureBundle.deserialise(SIGNATURE_BUNDLE_SERIALISED);

        await bundle.verify(VERIFY_PLAINTEXT, SERVICE_OID, date, dnssecChainFixture.trustAnchors);

        expect(bundleVerifySpy).toHaveBeenCalledWith(
          expect.anything(),
          expect.toSatisfy<DatePeriod>((period) => period.start === date && period.end === date),
          expect.anything(),
        );
      });

      test('Period should have start date before end date', async () => {
        const invalidExpiryDate = subSeconds(datePeriod.start, 1);
        const period: IDatePeriod = { start: datePeriod.start, end: invalidExpiryDate };
        const bundle = SignatureBundle.deserialise(SIGNATURE_BUNDLE_SERIALISED);

        await expect(async () =>
          bundle.verify(VERIFY_PLAINTEXT, SERVICE_OID, period, dnssecChainFixture.trustAnchors),
        ).rejects.toThrowWithMessage(
          VeraidError,
          'Verification expiry date cannot be before start date',
        );
      });

      test('Period should overlap with that of signature', async () => {
        const signaturePeriod = DatePeriod.init(
          subSeconds(datePeriod.start, 2),
          subSeconds(datePeriod.start, 1),
        );
        const testBundle = MemberIdBundle.deserialise(MEMBER_ID_BUNDLE);
        const periodSignatureBundle = await SignatureBundle.sign(
          VERIFY_PLAINTEXT,
          SERVICE_OID,
          testBundle,
          MEMBER_KEY_PAIR.privateKey,
          signaturePeriod.end,
          { startDate: signaturePeriod.start },
        );
        const signatureBundleSerialised = periodSignatureBundle.serialise();
        const bundle = SignatureBundle.deserialise(signatureBundleSerialised);

        await expect(async () =>
          bundle.verify(VERIFY_PLAINTEXT, SERVICE_OID, datePeriod, dnssecChainFixture.trustAnchors),
        ).rejects.toThrowWithMessage(
          VeraidError,
          `Signature period (${signaturePeriod.toString()}) ` +
            `does not overlap with required period (${datePeriod.toString()})`,
        );
      });

      test('Period should overlap with that of member certificate', async () => {
        const bundleVerifySpy = jest.spyOn(MemberIdBundle.prototype, 'verify');
        const verificationPeriod = DatePeriod.init(subSeconds(datePeriod.end, 1), datePeriod.end);
        const otherMemberCertificate = await issueMemberCertificate(
          MEMBER_NAME,
          MEMBER_KEY_PAIR.publicKey,
          orgCertificateSerialised,
          ORG_KEY_PAIR.privateKey,
          subSeconds(verificationPeriod.start, 1),
          { startDate: datePeriod.start },
        );
        const testMemberIdBundle = serialiseMemberIdBundle(
          otherMemberCertificate,
          orgCertificateSerialised,
          DNSSEC_CHAIN_SERIALISED,
        );
        const testBundle = MemberIdBundle.deserialise(testMemberIdBundle);
        const certSignatureBundle = await SignatureBundle.sign(
          VERIFY_PLAINTEXT,
          SERVICE_OID,
          testBundle,
          MEMBER_KEY_PAIR.privateKey,
          datePeriod.end,
          { startDate: datePeriod.start },
        );
        const signatureBundleSerialised = certSignatureBundle.serialise();
        const bundle = SignatureBundle.deserialise(signatureBundleSerialised);

        await expect(async () =>
          bundle.verify(
            VERIFY_PLAINTEXT,
            SERVICE_OID,
            verificationPeriod,
            dnssecChainFixture.trustAnchors,
          ),
        ).rejects.toThrowWithMessage(VeraidError, 'Member id bundle is invalid');
        expect(bundleVerifySpy).toHaveBeenCalledWith(
          expect.anything(),
          datePeriod.intersect(verificationPeriod),
          expect.anything(),
        );
      });
    });

    describe('Plaintext', () => {
      test('Verification should fail if plaintext is attached and passed', async () => {
        const testBundle = MemberIdBundle.deserialise(MEMBER_ID_BUNDLE);
        const attachedPlaintextBundle = await SignatureBundle.sign(
          VERIFY_PLAINTEXT,
          SERVICE_OID,
          testBundle,
          MEMBER_KEY_PAIR.privateKey,
          datePeriod.end,
          { shouldEncapsulatePlaintext: true },
        );
        const signatureBundleSerialised = attachedPlaintextBundle.serialise();
        const bundle = SignatureBundle.deserialise(signatureBundleSerialised);

        const error = await getPromiseRejection(
          async () =>
            bundle.verify(
              VERIFY_PLAINTEXT,
              SERVICE_OID,
              datePeriod,
              dnssecChainFixture.trustAnchors,
            ),
          VeraidError,
        );

        expect(error.cause).toBeInstanceOf(CmsError);
      });

      test('Verification should fail if plaintext is detached and not passed', async () => {
        const testBundle = MemberIdBundle.deserialise(MEMBER_ID_BUNDLE);
        const detachedPlaintextBundle = await SignatureBundle.sign(
          VERIFY_PLAINTEXT,
          SERVICE_OID,
          testBundle,
          MEMBER_KEY_PAIR.privateKey,
          datePeriod.end,
          { shouldEncapsulatePlaintext: false },
        );
        const signatureBundleSerialised = detachedPlaintextBundle.serialise();
        const bundle = SignatureBundle.deserialise(signatureBundleSerialised);

        const error = await getPromiseRejection(
          async () =>
            bundle.verify(undefined, SERVICE_OID, datePeriod, dnssecChainFixture.trustAnchors),
          VeraidError,
        );

        expect(error.cause).toBeInstanceOf(CmsError);
      });
    });

    describe('Valid result', () => {
      test('Plaintext should be taken from bundle if attached', async () => {
        const testBundle = MemberIdBundle.deserialise(MEMBER_ID_BUNDLE);
        const attachedPlaintextBundle2 = await SignatureBundle.sign(
          VERIFY_PLAINTEXT,
          SERVICE_OID,
          testBundle,
          MEMBER_KEY_PAIR.privateKey,
          datePeriod.end,
          { shouldEncapsulatePlaintext: true },
        );
        const signatureBundleSerialised = attachedPlaintextBundle2.serialise();
        const bundle = SignatureBundle.deserialise(signatureBundleSerialised);

        const { plaintext } = await bundle.verify(
          undefined,
          SERVICE_OID,
          datePeriod,
          dnssecChainFixture.trustAnchors,
        );

        expect(Buffer.from(plaintext)).toMatchObject(Buffer.from(VERIFY_PLAINTEXT));
      });

      test('Plaintext should be taken from parameter if detached', async () => {
        const bundle = SignatureBundle.deserialise(SIGNATURE_BUNDLE_SERIALISED);

        const { plaintext } = await bundle.verify(
          VERIFY_PLAINTEXT,
          SERVICE_OID,
          datePeriod,
          dnssecChainFixture.trustAnchors,
        );

        expect(Buffer.from(plaintext)).toMatchObject(Buffer.from(VERIFY_PLAINTEXT));
      });

      test('Organisation name should be output', async () => {
        const bundle = SignatureBundle.deserialise(SIGNATURE_BUNDLE_SERIALISED);

        const {
          member: { organisation },
        } = await bundle.verify(
          VERIFY_PLAINTEXT,
          SERVICE_OID,
          datePeriod,
          dnssecChainFixture.trustAnchors,
        );

        expect(organisation).toStrictEqual(ORG_NAME);
      });

      test('User name should be output if member is a user', async () => {
        const bundle = SignatureBundle.deserialise(SIGNATURE_BUNDLE_SERIALISED);

        const {
          member: { user },
        } = await bundle.verify(
          VERIFY_PLAINTEXT,
          SERVICE_OID,
          datePeriod,
          dnssecChainFixture.trustAnchors,
        );

        expect(user).toStrictEqual(MEMBER_NAME);
      });

      test('User name should not be output if member is a bot', async () => {
        const botCertificate = await issueMemberCertificate(
          undefined,
          MEMBER_KEY_PAIR.publicKey,
          orgCertificateSerialised,
          ORG_KEY_PAIR.privateKey,
          datePeriod.end,
          { startDate: datePeriod.start },
        );
        const botMemberIdBundle = serialiseMemberIdBundle(
          botCertificate,
          orgCertificateSerialised,
          DNSSEC_CHAIN_SERIALISED,
        );
        const botBundle = MemberIdBundle.deserialise(botMemberIdBundle);
        const botSignatureBundle = await SignatureBundle.sign(
          VERIFY_PLAINTEXT,
          SERVICE_OID,
          botBundle,
          MEMBER_KEY_PAIR.privateKey,
          datePeriod.end,
          { startDate: datePeriod.start },
        );
        const signatureBundleSerialised = botSignatureBundle.serialise();
        const bundle = SignatureBundle.deserialise(signatureBundleSerialised);

        const {
          member: { user },
        } = await bundle.verify(
          VERIFY_PLAINTEXT,
          SERVICE_OID,
          datePeriod,
          dnssecChainFixture.trustAnchors,
        );

        expect(user).toBeUndefined();
      });

      test('Signature should be deemed as signed by member', async () => {
        const bundle = SignatureBundle.deserialise(SIGNATURE_BUNDLE_SERIALISED);

        const { wasSignedByMember } = await bundle.verify(
          VERIFY_PLAINTEXT,
          SERVICE_OID,
          datePeriod,
          dnssecChainFixture.trustAnchors,
        );

        expect(wasSignedByMember).toBe(true);
      });
    });
  });
});
