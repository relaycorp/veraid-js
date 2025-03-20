/* eslint-disable max-lines */
import { AsnParser, AsnSerializer } from '@peculiar/asn1-schema';
import { subSeconds, setMilliseconds } from 'date-fns';
import { type OctetString, Null, type Utf8String, type Sequence } from 'asn1js';
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

import { bufferToArray } from './utils/buffers.js';
import { VeraidError } from './VeraidError.js';
import { SignatureBundleSchema } from './schemas/SignatureBundleSchema.js';
import { SignedData } from './utils/cms/SignedData.js';
import { CMS_OIDS, VERAID_OIDS } from './oids.js';
import { SignatureMetadataSchema } from './schemas/SignatureMetadataSchema.js';
import { derDeserialize } from './utils/asn1.js';
import { MemberIdBundle } from './memberIdBundle/MemberIdBundle.js';
import { SignatureBundle } from './SignatureBundle.js';
import { OrganisationSigner } from './OrganisationSigner.js';
import { DatePeriod, type IDatePeriod } from './dates.js';
import { DatePeriodSchema } from './schemas/DatePeriodSchema.js';
import { issueMemberCertificate, BOT_NAME } from './pki/member.js';
import { generateTxtRdata } from './dns/rdataSerialisation.js';
import CmsError from './utils/cms/CmsError.js';
import { VeraidDnssecChain } from './dns/VeraidDnssecChain.js';

const PLAINTEXT = arrayBufferFrom('Hello world');

const {
  orgCertificate,
  memberCertificate,
  dnssecChainFixture,
  datePeriod: DATE_PERIOD,
} = await generateMemberIdFixture();
const VERAID_DNSSEC_CHAIN = new VeraidDnssecChain(
  orgCertificate.commonName,
  dnssecChainFixture.responses.map(serialiseMessage).map(bufferToArray),
);
const MEMBER_ID_BUNDLE = new MemberIdBundle(VERAID_DNSSEC_CHAIN, orgCertificate, memberCertificate);

describe('SignatureBundle', () => {
  describe('sign', () => {
    function getSignedData(contentInfo: ContentInfo) {
      expect(contentInfo.contentType).toStrictEqual(CMS_OIDS.SIGNED_DATA);
      return AsnParser.parse(contentInfo.content, SignedDataSchema);
    }

    test('Version should be 0', async () => {
      const signatureBundle = await SignatureBundle.sign(
        PLAINTEXT,
        SERVICE_OID,
        MEMBER_ID_BUNDLE,
        MEMBER_KEY_PAIR.privateKey,
        DATE_PERIOD.end,
      );

      const signatureSerialised = signatureBundle.serialise();
      const { version } = AsnParser.parse(signatureSerialised, SignatureBundleSchema);
      expect(version).toBe(0);
    });

    test('DNSSEC chain should be attached', async () => {
      const signatureBundle = await SignatureBundle.sign(
        PLAINTEXT,
        SERVICE_OID,
        MEMBER_ID_BUNDLE,
        MEMBER_KEY_PAIR.privateKey,
        DATE_PERIOD.end,
      );

      expect(signatureBundle.dnssecChain.toSchema()).toStrictEqual(VERAID_DNSSEC_CHAIN.toSchema());
    });

    test('Organisation certificate should be attached', async () => {
      const signatureBundle = await SignatureBundle.sign(
        PLAINTEXT,
        SERVICE_OID,
        MEMBER_ID_BUNDLE,
        MEMBER_KEY_PAIR.privateKey,
        DATE_PERIOD.end,
      );

      expect(signatureBundle.orgCertificate.isEqual(orgCertificate)).toBeTrue();
    });

    describe('Signature', () => {
      test('Plaintext should be signed with specified private key', async () => {
        const signatureBundle = await SignatureBundle.sign(
          PLAINTEXT,
          SERVICE_OID,
          MEMBER_ID_BUNDLE,
          MEMBER_KEY_PAIR.privateKey,
          DATE_PERIOD.end,
        );

        const signatureSerialised = signatureBundle.serialise();
        const { signature } = AsnParser.parse(signatureSerialised, SignatureBundleSchema);
        const signedData = SignedData.deserialize(AsnSerializer.serialize(signature));
        await signedData.verify(PLAINTEXT);
        expect(signedData.signerCertificate!.isEqual(memberCertificate)).toBeTrue();
      });

      test("Signer certificate should be attached if it's a member signature", async () => {
        const signatureBundle = await SignatureBundle.sign(
          PLAINTEXT,
          SERVICE_OID,
          MEMBER_ID_BUNDLE,
          MEMBER_KEY_PAIR.privateKey,
          DATE_PERIOD.end,
        );

        const signedData = SignedData.deserialize(
          AsnSerializer.serialize(signatureBundle.signature),
        );
        expect(signedData.signerCertificate!.isEqual(memberCertificate)).toBeTrue();
      });

      test('Member signature should not contain attribution attribute', async () => {
        const signatureBundle = await SignatureBundle.sign(
          PLAINTEXT,
          SERVICE_OID,
          MEMBER_ID_BUNDLE,
          MEMBER_KEY_PAIR.privateKey,
          DATE_PERIOD.end,
        );

        const signatureSerialised = signatureBundle.serialise();
        const { signature } = AsnParser.parse(signatureSerialised, SignatureBundleSchema);
        const signedData = SignedData.deserialize(AsnSerializer.serialize(signature));
        const memberAttributionAttr = signedData.getSignedAttribute(
          VERAID_OIDS.MEMBER_ATTRIBUTION_ATTR,
        );
        expect(memberAttributionAttr).toBeNull();
      });

      test('Org signature should not include certificates', async () => {
        const orgSigner = new OrganisationSigner(VERAID_DNSSEC_CHAIN, orgCertificate);

        const signatureBundle = await SignatureBundle.sign(
          PLAINTEXT,
          SERVICE_OID,
          orgSigner,
          ORG_KEY_PAIR.privateKey,
          DATE_PERIOD.end,
        );

        const signatureSerialised = signatureBundle.serialise();
        const { signature } = AsnParser.parse(signatureSerialised, SignatureBundleSchema);
        const signedDataSchema = getSignedData(signature);
        expect(signedDataSchema.certificates).toHaveLength(0);
      });

      test('Plaintext should be detached by default', async () => {
        const signatureBundle = await SignatureBundle.sign(
          PLAINTEXT,
          SERVICE_OID,
          MEMBER_ID_BUNDLE,
          MEMBER_KEY_PAIR.privateKey,
          DATE_PERIOD.end,
        );

        const signatureSerialised = signatureBundle.serialise();
        const { signature } = AsnParser.parse(signatureSerialised, SignatureBundleSchema);
        const { encapContentInfo } = getSignedData(signature);
        expect(encapContentInfo.eContent).toBeUndefined();
      });

      test('Plaintext should be attached if requested', async () => {
        const signatureBundle = await SignatureBundle.sign(
          PLAINTEXT,
          SERVICE_OID,
          MEMBER_ID_BUNDLE,
          MEMBER_KEY_PAIR.privateKey,
          DATE_PERIOD.end,
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

      test('Organisation signature should be attributed to bot by default', async () => {
        const orgSigner = new OrganisationSigner(VERAID_DNSSEC_CHAIN, orgCertificate);

        const signatureBundle = await SignatureBundle.sign(
          PLAINTEXT,
          SERVICE_OID,
          orgSigner,
          ORG_KEY_PAIR.privateKey,
          DATE_PERIOD.end,
        );

        const signatureSerialised = signatureBundle.serialise();
        const { signature } = AsnParser.parse(signatureSerialised, SignatureBundleSchema);
        const signedData = SignedData.deserialize(AsnSerializer.serialize(signature));
        const memberAttributionAttr = signedData.getSignedAttribute(
          VERAID_OIDS.MEMBER_ATTRIBUTION_ATTR,
        );
        expect(memberAttributionAttr).not.toBeNull();
        expect((memberAttributionAttr![0] as Utf8String).getValue()).toBe(BOT_NAME);
      });

      test('Organisation signature may be attributed to user if requested', async () => {
        const attributedMemberName = 'alice';
        const orgSigner = new OrganisationSigner(
          VERAID_DNSSEC_CHAIN,
          orgCertificate,
          attributedMemberName,
        );

        const signatureBundle = await SignatureBundle.sign(
          PLAINTEXT,
          SERVICE_OID,
          orgSigner,
          ORG_KEY_PAIR.privateKey,
          DATE_PERIOD.end,
        );

        const signatureSerialised = signatureBundle.serialise();
        const { signature } = AsnParser.parse(signatureSerialised, SignatureBundleSchema);
        const signedData = SignedData.deserialize(AsnSerializer.serialize(signature));
        const memberAttributionAttr = signedData.getSignedAttribute(
          VERAID_OIDS.MEMBER_ATTRIBUTION_ATTR,
        );
        expect(memberAttributionAttr).not.toBeNull();
        expect((memberAttributionAttr![0] as Utf8String).getValue()).toBe(attributedMemberName);
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
          const signatureBundle = await SignatureBundle.sign(
            PLAINTEXT,
            SERVICE_OID,
            MEMBER_ID_BUNDLE,
            MEMBER_KEY_PAIR.privateKey,
            DATE_PERIOD.end,
          );

          const signatureSerialised = signatureBundle.serialise();
          const { signature } = AsnParser.parse(signatureSerialised, SignatureBundleSchema);
          const { serviceOid } = getSignatureMetadata(signature);
          expect(serviceOid).toStrictEqual(SERVICE_OID);
        });

        test('Expiry date should be attached', async () => {
          const signatureBundle = await SignatureBundle.sign(
            PLAINTEXT,
            SERVICE_OID,
            MEMBER_ID_BUNDLE,
            MEMBER_KEY_PAIR.privateKey,
            DATE_PERIOD.end,
          );

          const signatureSerialised = signatureBundle.serialise();
          const { signature } = AsnParser.parse(signatureSerialised, SignatureBundleSchema);
          const { validityPeriod } = getSignatureMetadata(signature);
          expect(validityPeriod.end).toStrictEqual(DATE_PERIOD.end);
        });

        test('Start date should default to the current time', async () => {
          const beforeSignatureDate = setMilliseconds(new Date(), 0);
          const signatureBundle = await SignatureBundle.sign(
            PLAINTEXT,
            SERVICE_OID,
            MEMBER_ID_BUNDLE,
            MEMBER_KEY_PAIR.privateKey,
            DATE_PERIOD.end,
          );
          const afterSignatureDate = new Date();

          const signatureSerialised = signatureBundle.serialise();
          const { signature } = AsnParser.parse(signatureSerialised, SignatureBundleSchema);
          const { validityPeriod } = getSignatureMetadata(signature);
          expect(validityPeriod.start).toBeBetween(beforeSignatureDate, afterSignatureDate);
        });

        test('Any explicit start date should be honoured', async () => {
          const startDate = subSeconds(DATE_PERIOD.start, 1);
          const signatureBundle = await SignatureBundle.sign(
            PLAINTEXT,
            SERVICE_OID,
            MEMBER_ID_BUNDLE,
            MEMBER_KEY_PAIR.privateKey,
            DATE_PERIOD.end,
            { startDate },
          );

          const signatureSerialised = signatureBundle.serialise();
          const { signature } = AsnParser.parse(signatureSerialised, SignatureBundleSchema);
          const { validityPeriod } = getSignatureMetadata(signature);
          expect(validityPeriod.start).toStrictEqual(startDate);
        });

        test('Start date after expiry date should be refused', async () => {
          const invalidExpiryDate = subSeconds(DATE_PERIOD.start, 1);
          await expect(async () =>
            SignatureBundle.sign(
              PLAINTEXT,
              SERVICE_OID,
              MEMBER_ID_BUNDLE,
              MEMBER_KEY_PAIR.privateKey,
              invalidExpiryDate,
              { startDate: DATE_PERIOD.start },
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
      const signatureBundle = await SignatureBundle.sign(
        PLAINTEXT,
        SERVICE_OID,
        MEMBER_ID_BUNDLE,
        MEMBER_KEY_PAIR.privateKey,
        DATE_PERIOD.end,
      );

      const serialisation = signatureBundle.serialise();

      const bundleDeserialised = AsnParser.parse(serialisation, SignatureBundleSchema);
      expect(bundleDeserialised.version).toBe(0);
    });

    test('DNSSEC chain should be included', async () => {
      const signatureBundle = await SignatureBundle.sign(
        PLAINTEXT,
        SERVICE_OID,
        MEMBER_ID_BUNDLE,
        MEMBER_KEY_PAIR.privateKey,
        DATE_PERIOD.end,
      );

      const serialisation = signatureBundle.serialise();

      const bundleDeserialised = AsnParser.parse(serialisation, SignatureBundleSchema);
      expect(Buffer.from(AsnSerializer.serialize(bundleDeserialised.dnssecChain))).toStrictEqual(
        Buffer.from(VERAID_DNSSEC_CHAIN.serialise()),
      );
    });

    test('Organisation certificate should be included', async () => {
      const signatureBundle = await SignatureBundle.sign(
        PLAINTEXT,
        SERVICE_OID,
        MEMBER_ID_BUNDLE,
        MEMBER_KEY_PAIR.privateKey,
        DATE_PERIOD.end,
      );

      const serialisation = signatureBundle.serialise();

      const bundleDeserialised = AsnParser.parse(serialisation, SignatureBundleSchema);
      expect(bundleDeserialised.organisationCertificate).toStrictEqual(orgCertificate.toSchema());
    });

    test('Signature should be included', async () => {
      const signatureBundle = await SignatureBundle.sign(
        PLAINTEXT,
        SERVICE_OID,
        MEMBER_ID_BUNDLE,
        MEMBER_KEY_PAIR.privateKey,
        DATE_PERIOD.end,
      );

      const serialisation = signatureBundle.serialise();

      const bundleDeserialised = AsnParser.parse(serialisation, SignatureBundleSchema);
      expect(bundleDeserialised.signature).not.toBeNull();
      expect(bundleDeserialised.signature.contentType).toStrictEqual(CMS_OIDS.SIGNED_DATA);
    });
  });

  describe('deserialise', () => {
    test('Should throw error if version is not 0', async () => {
      const signatureBundle = await SignatureBundle.sign(
        PLAINTEXT,
        SERVICE_OID,
        MEMBER_ID_BUNDLE,
        MEMBER_KEY_PAIR.privateKey,
        DATE_PERIOD.end,
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
      const signatureBundle = await SignatureBundle.sign(
        PLAINTEXT,
        SERVICE_OID,
        MEMBER_ID_BUNDLE,
        MEMBER_KEY_PAIR.privateKey,
        DATE_PERIOD.end,
      );
      const serialisation = signatureBundle.serialise();

      const deserialisedBundle = SignatureBundle.deserialise(serialisation);

      const { dnssecChain: deserialisedDnssecChain } = deserialisedBundle;
      expect(Buffer.from(deserialisedDnssecChain.serialise())).toStrictEqual(
        Buffer.from(VERAID_DNSSEC_CHAIN.serialise()),
      );
    });

    test('Should correctly deserialise organisation certificate', async () => {
      const signatureBundle = await SignatureBundle.sign(
        PLAINTEXT,
        SERVICE_OID,
        MEMBER_ID_BUNDLE,
        MEMBER_KEY_PAIR.privateKey,
        DATE_PERIOD.end,
      );
      const serialisation = signatureBundle.serialise();

      const deserialisedBundle = SignatureBundle.deserialise(serialisation);

      const { orgCertificate: deserialisedOrgCertificate } = deserialisedBundle;
      expect(deserialisedOrgCertificate.toSchema()).toStrictEqual(orgCertificate.toSchema());
    });

    test('Should correctly deserialise signature', async () => {
      const signatureBundle = await SignatureBundle.sign(
        PLAINTEXT,
        SERVICE_OID,
        MEMBER_ID_BUNDLE,
        MEMBER_KEY_PAIR.privateKey,
        DATE_PERIOD.end,
      );
      const serialisation = signatureBundle.serialise();

      const deserialisedBundle = SignatureBundle.deserialise(serialisation);

      const { signature } = deserialisedBundle as unknown as { signature: ContentInfo };
      expect(signature.contentType).toStrictEqual(CMS_OIDS.SIGNED_DATA);

      const signedData = SignedData.deserialize(AsnSerializer.serialize(signature));
      await expect(signedData.verify(PLAINTEXT)).resolves.not.toThrow();
    });

    test('Should preserve version 0', async () => {
      const signatureBundle = await SignatureBundle.sign(
        PLAINTEXT,
        SERVICE_OID,
        MEMBER_ID_BUNDLE,
        MEMBER_KEY_PAIR.privateKey,
        DATE_PERIOD.end,
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

    function generateTestMetadata(serviceOid: string, startDate: Date, expiryDate: Date): Sequence {
      const metadataSchema = new SignatureMetadataSchema();
      metadataSchema.serviceOid = serviceOid;
      const datePeriod = new DatePeriodSchema();
      datePeriod.start = startDate;
      datePeriod.end = expiryDate;
      metadataSchema.validityPeriod = datePeriod;
      return derDeserialize(AsnSerializer.serialize(metadataSchema)) as Sequence;
    }

    function replaceBundleAttribute(
      signatureBundle: SignatureBundle,
      attributes: Partial<SignatureBundleAttributeSet>,
    ): SignatureBundle {
      const newDnssecChain = attributes.dnssecResponses
        ? new VeraidDnssecChain(
            signatureBundle.orgCertificate.commonName,
            attributes.dnssecResponses.map(serialiseMessage).map(arrayBufferFrom),
          )
        : signatureBundle.dnssecChain;

      const signature = attributes.signedData
        ? AsnParser.parse(attributes.signedData.serialize(), ContentInfo)
        : signatureBundle.signature;

      return new SignatureBundle(newDnssecChain, signatureBundle.orgCertificate, signature);
    }

    let stubMemberSignatureBundle: SignatureBundle;
    beforeAll(async () => {
      stubMemberSignatureBundle = await SignatureBundle.sign(
        PLAINTEXT,
        SERVICE_OID,
        MEMBER_ID_BUNDLE,
        MEMBER_KEY_PAIR.privateKey,
        DATE_PERIOD.end,
        { startDate: DATE_PERIOD.start },
      );
    });

    test('Metadata attribute should be present in signature', async () => {
      const signedData = await SignedData.sign(
        PLAINTEXT,
        MEMBER_KEY_PAIR.privateKey,
        memberCertificate,
        [memberCertificate],
        { shouldEncapsulatePlaintext: false },
      );
      const bundle = replaceBundleAttribute(stubMemberSignatureBundle, { signedData });

      await expect(async () =>
        bundle.verify(PLAINTEXT, SERVICE_OID, DATE_PERIOD, dnssecChainFixture.trustAnchors),
      ).rejects.toThrowWithMessage(VeraidError, 'Signature metadata is missing');
    });

    test('Metadata attribute should be well-formed', async () => {
      const attribute = new PkijsAttribute({
        type: VERAID_OIDS.SIGNATURE_METADATA_ATTR,
        values: [new Null()],
      });
      const signedData = await SignedData.sign(
        PLAINTEXT,
        MEMBER_KEY_PAIR.privateKey,
        memberCertificate,
        [memberCertificate],
        {
          shouldEncapsulatePlaintext: false,
          extraSignedAttrs: [attribute],
        },
      );
      const bundle = replaceBundleAttribute(stubMemberSignatureBundle, { signedData });

      await expect(async () =>
        bundle.verify(PLAINTEXT, SERVICE_OID, DATE_PERIOD, dnssecChainFixture.trustAnchors),
      ).rejects.toThrowWithMessage(VeraidError, 'Signature metadata is malformed');
    });

    test('Metadata should contain valid validity period', async () => {
      const metadata = new SignatureMetadataSchema();
      metadata.serviceOid = SERVICE_OID;
      metadata.validityPeriod = new DatePeriodSchema();
      metadata.validityPeriod.start = DATE_PERIOD.start;
      metadata.validityPeriod.end = subSeconds(DATE_PERIOD.start, 1); // Invalid
      const attribute = new PkijsAttribute({
        type: VERAID_OIDS.SIGNATURE_METADATA_ATTR,
        values: [derDeserialize(AsnSerializer.serialize(metadata))],
      });
      const signedData = await SignedData.sign(
        PLAINTEXT,
        MEMBER_KEY_PAIR.privateKey,
        memberCertificate,
        [memberCertificate],
        {
          shouldEncapsulatePlaintext: false,
          extraSignedAttrs: [attribute],
        },
      );
      const bundle = replaceBundleAttribute(stubMemberSignatureBundle, { signedData });

      await expect(async () =>
        bundle.verify(PLAINTEXT, SERVICE_OID, DATE_PERIOD, dnssecChainFixture.trustAnchors),
      ).rejects.toThrowWithMessage(VeraidError, 'Signature validity period ends before it starts');
    });

    test('Signature should correspond to specified plaintext', async () => {
      const differentPlaintext = bufferToArray(Buffer.from(PLAINTEXT, 1));

      const error = await getPromiseRejection(
        async () =>
          stubMemberSignatureBundle.verify(
            differentPlaintext,
            SERVICE_OID,
            DATE_PERIOD,
            dnssecChainFixture.trustAnchors,
          ),
        VeraidError,
      );

      expectErrorToEqual(
        error,
        new VeraidError('Signature is invalid', { cause: expect.any(CmsError) }),
      );
    });

    describe('Service OID', () => {
      test('Service OID should match that of the signature metadata', async () => {
        const differentServiceOid = `${SERVICE_OID}.1`;

        await expect(async () =>
          stubMemberSignatureBundle.verify(
            PLAINTEXT,
            differentServiceOid,
            DATE_PERIOD,
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
          DATE_PERIOD,
        );
        const bundle = replaceBundleAttribute(stubMemberSignatureBundle, { dnssecResponses });

        await expect(async () =>
          bundle.verify(PLAINTEXT, SERVICE_OID, DATE_PERIOD, trustAnchors),
        ).rejects.toThrowWithMessage(VeraidError, 'Chain verification failed');
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

        await stubMemberSignatureBundle.verify(
          PLAINTEXT,
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

        await stubMemberSignatureBundle.verify(
          PLAINTEXT,
          SERVICE_OID,
          date,
          dnssecChainFixture.trustAnchors,
        );

        expect(bundleVerifySpy).toHaveBeenCalledWith(
          expect.anything(),
          expect.toSatisfy<DatePeriod>((period) => period.start === date && period.end === date),
          expect.anything(),
        );
      });

      test('Period should have start date before end date', async () => {
        const invalidExpiryDate = subSeconds(DATE_PERIOD.start, 1);
        const period: IDatePeriod = { start: DATE_PERIOD.start, end: invalidExpiryDate };

        await expect(async () =>
          stubMemberSignatureBundle.verify(
            PLAINTEXT,
            SERVICE_OID,
            period,
            dnssecChainFixture.trustAnchors,
          ),
        ).rejects.toThrowWithMessage(
          VeraidError,
          'Verification expiry date cannot be before start date',
        );
      });

      test('Period should overlap with that of signature', async () => {
        const signaturePeriod = DatePeriod.init(
          subSeconds(DATE_PERIOD.start, 2),
          subSeconds(DATE_PERIOD.start, 1),
        );
        const periodSignatureBundle = await SignatureBundle.sign(
          PLAINTEXT,
          SERVICE_OID,
          MEMBER_ID_BUNDLE,
          MEMBER_KEY_PAIR.privateKey,
          signaturePeriod.end,
          { startDate: signaturePeriod.start },
        );

        await expect(async () =>
          periodSignatureBundle.verify(
            PLAINTEXT,
            SERVICE_OID,
            DATE_PERIOD,
            dnssecChainFixture.trustAnchors,
          ),
        ).rejects.toThrowWithMessage(
          VeraidError,
          `Signature period (${signaturePeriod.toString()}) ` +
            `does not overlap with required period (${DATE_PERIOD.toString()})`,
        );
      });

      test('Period should overlap with that of member certificate', async () => {
        const bundleVerifySpy = jest.spyOn(MemberIdBundle.prototype, 'verify');
        const verificationPeriod = DatePeriod.init(subSeconds(DATE_PERIOD.end, 1), DATE_PERIOD.end);
        const otherMemberCertificate = await issueMemberCertificate(
          MEMBER_NAME,
          MEMBER_KEY_PAIR.publicKey,
          orgCertificate,
          ORG_KEY_PAIR.privateKey,
          subSeconds(verificationPeriod.start, 1),
          { startDate: DATE_PERIOD.start },
        );
        const testBundle = new MemberIdBundle(
          VERAID_DNSSEC_CHAIN,
          orgCertificate,
          otherMemberCertificate,
        );
        const certSignatureBundle = await SignatureBundle.sign(
          PLAINTEXT,
          SERVICE_OID,
          testBundle,
          MEMBER_KEY_PAIR.privateKey,
          DATE_PERIOD.end,
          { startDate: DATE_PERIOD.start },
        );

        await expect(async () =>
          certSignatureBundle.verify(
            PLAINTEXT,
            SERVICE_OID,
            verificationPeriod,
            dnssecChainFixture.trustAnchors,
          ),
        ).rejects.toThrowWithMessage(VeraidError, 'Chain verification failed');
        expect(bundleVerifySpy).toHaveBeenCalledWith(
          expect.anything(),
          DATE_PERIOD.intersect(verificationPeriod),
          expect.anything(),
        );
      });
    });

    describe('Plaintext', () => {
      test('Verification should fail if plaintext is attached and passed', async () => {
        const attachedPlaintextBundle = await SignatureBundle.sign(
          PLAINTEXT,
          SERVICE_OID,
          MEMBER_ID_BUNDLE,
          MEMBER_KEY_PAIR.privateKey,
          DATE_PERIOD.end,
          { shouldEncapsulatePlaintext: true },
        );

        const error = await getPromiseRejection(
          async () =>
            attachedPlaintextBundle.verify(
              PLAINTEXT,
              SERVICE_OID,
              DATE_PERIOD,
              dnssecChainFixture.trustAnchors,
            ),
          VeraidError,
        );

        expect(error.cause).toBeInstanceOf(CmsError);
      });

      test('Verification should fail if plaintext is detached and not passed', async () => {
        const detachedPlaintextBundle = await SignatureBundle.sign(
          PLAINTEXT,
          SERVICE_OID,
          MEMBER_ID_BUNDLE,
          MEMBER_KEY_PAIR.privateKey,
          DATE_PERIOD.end,
          { shouldEncapsulatePlaintext: false },
        );

        const error = await getPromiseRejection(
          async () =>
            detachedPlaintextBundle.verify(
              undefined,
              SERVICE_OID,
              DATE_PERIOD,
              dnssecChainFixture.trustAnchors,
            ),
          VeraidError,
        );

        expect(error.cause).toBeInstanceOf(CmsError);
      });
    });

    describe('Member signatures', () => {
      test('Member certificate should be attached to SignedData value', async () => {
        const metadata = generateTestMetadata(SERVICE_OID, DATE_PERIOD.start, DATE_PERIOD.end);
        const metadataAttribute = new PkijsAttribute({
          type: VERAID_OIDS.SIGNATURE_METADATA_ATTR,
          values: [metadata],
        });
        const signedData = await SignedData.sign(
          PLAINTEXT,
          MEMBER_KEY_PAIR.privateKey,
          memberCertificate,
          [], // Empty certificates array
          {
            shouldEncapsulatePlaintext: false,
            extraSignedAttrs: [metadataAttribute],
          },
        );
        const bundle = replaceBundleAttribute(stubMemberSignatureBundle, { signedData });

        await expect(async () =>
          bundle.verify(PLAINTEXT, SERVICE_OID, DATE_PERIOD, dnssecChainFixture.trustAnchors),
        ).rejects.toThrowWithMessage(VeraidError, 'Member signature is missing signer certificate');
      });

      test('Member id bundle should be valid', async () => {
        const invalidBundle = new MemberIdBundle(
          VERAID_DNSSEC_CHAIN,
          memberCertificate, // Invalid
          memberCertificate,
        );
        const invalidSignatureBundle = await SignatureBundle.sign(
          PLAINTEXT,
          SERVICE_OID,
          invalidBundle,
          MEMBER_KEY_PAIR.privateKey,
          DATE_PERIOD.end,
          { startDate: DATE_PERIOD.start },
        );

        const error = await getPromiseRejection(
          async () =>
            invalidSignatureBundle.verify(
              PLAINTEXT,
              SERVICE_OID,
              DATE_PERIOD,
              dnssecChainFixture.trustAnchors,
            ),
          VeraidError,
        );

        expectErrorToEqual(
          error,
          new VeraidError('Chain verification failed', { cause: expect.any(VeraidError) }),
        );
      });
    });

    describe('Organisation signatures', () => {
      test('Member attribution attribute should be well-formed', async () => {
        const metadata = generateTestMetadata(SERVICE_OID, DATE_PERIOD.start, DATE_PERIOD.end);
        const metadataAttribute = new PkijsAttribute({
          type: VERAID_OIDS.SIGNATURE_METADATA_ATTR,
          values: [metadata],
        });
        const memberAttributionAttribute = new PkijsAttribute({
          type: VERAID_OIDS.MEMBER_ATTRIBUTION_ATTR,
          values: [new Null()],
        });
        const signedData = await SignedData.sign(
          PLAINTEXT,
          MEMBER_KEY_PAIR.privateKey,
          memberCertificate,
          [],
          {
            shouldEncapsulatePlaintext: false,
            extraSignedAttrs: [metadataAttribute, memberAttributionAttribute],
          },
        );
        const bundle = replaceBundleAttribute(stubMemberSignatureBundle, { signedData });

        await expect(async () =>
          bundle.verify(PLAINTEXT, SERVICE_OID, DATE_PERIOD, dnssecChainFixture.trustAnchors),
        ).rejects.toThrowWithMessage(VeraidError, 'Member attribution attribute is malformed');
      });

      test('Organisation signer should be valid', async () => {
        const orgSigner = new OrganisationSigner(
          new VeraidDnssecChain(orgCertificate.commonName, []), // Invalid
          orgCertificate,
        );
        const signatureBundle = await SignatureBundle.sign(
          PLAINTEXT,
          SERVICE_OID,
          orgSigner,
          ORG_KEY_PAIR.privateKey,
          DATE_PERIOD.end,
          { startDate: DATE_PERIOD.start },
        );

        const error = await getPromiseRejection(
          async () =>
            signatureBundle.verify(
              PLAINTEXT,
              SERVICE_OID,
              DATE_PERIOD,
              dnssecChainFixture.trustAnchors,
            ),
          VeraidError,
        );

        expectErrorToEqual(
          error,
          new VeraidError('Chain verification failed', { cause: expect.any(VeraidError) }),
        );
      });
    });

    describe('Valid result', () => {
      test('Plaintext should be taken from bundle if attached', async () => {
        const attachedPlaintextBundle2 = await SignatureBundle.sign(
          PLAINTEXT,
          SERVICE_OID,
          MEMBER_ID_BUNDLE,
          MEMBER_KEY_PAIR.privateKey,
          DATE_PERIOD.end,
          { shouldEncapsulatePlaintext: true },
        );

        const { plaintext } = await attachedPlaintextBundle2.verify(
          undefined,
          SERVICE_OID,
          DATE_PERIOD,
          dnssecChainFixture.trustAnchors,
        );

        expect(Buffer.from(plaintext)).toMatchObject(Buffer.from(PLAINTEXT));
      });

      test('Plaintext should be taken from parameter if detached', async () => {
        const { plaintext } = await stubMemberSignatureBundle.verify(
          PLAINTEXT,
          SERVICE_OID,
          DATE_PERIOD,
          dnssecChainFixture.trustAnchors,
        );

        expect(Buffer.from(plaintext)).toMatchObject(Buffer.from(PLAINTEXT));
      });

      test('Organisation name should be output', async () => {
        const {
          member: { organisation },
        } = await stubMemberSignatureBundle.verify(
          PLAINTEXT,
          SERVICE_OID,
          DATE_PERIOD,
          dnssecChainFixture.trustAnchors,
        );

        expect(organisation).toStrictEqual(ORG_NAME);
      });

      describe('Member signatures', () => {
        test('User name should be output if member is a user', async () => {
          const {
            member: { user },
          } = await stubMemberSignatureBundle.verify(
            PLAINTEXT,
            SERVICE_OID,
            DATE_PERIOD,
            dnssecChainFixture.trustAnchors,
          );

          expect(user).toStrictEqual(MEMBER_NAME);
        });

        test('User name should not be output if member is a bot', async () => {
          const botCertificate = await issueMemberCertificate(
            undefined,
            MEMBER_KEY_PAIR.publicKey,
            orgCertificate,
            ORG_KEY_PAIR.privateKey,
            DATE_PERIOD.end,
            { startDate: DATE_PERIOD.start },
          );
          const botBundle = new MemberIdBundle(VERAID_DNSSEC_CHAIN, orgCertificate, botCertificate);
          const botSignatureBundle = await SignatureBundle.sign(
            PLAINTEXT,
            SERVICE_OID,
            botBundle,
            MEMBER_KEY_PAIR.privateKey,
            DATE_PERIOD.end,
            { startDate: DATE_PERIOD.start },
          );

          const {
            member: { user },
          } = await botSignatureBundle.verify(
            PLAINTEXT,
            SERVICE_OID,
            DATE_PERIOD,
            dnssecChainFixture.trustAnchors,
          );

          expect(user).toBeUndefined();
        });

        test('Signature should be deemed as signed by member', async () => {
          const { wasSignedByMember } = await stubMemberSignatureBundle.verify(
            PLAINTEXT,
            SERVICE_OID,
            DATE_PERIOD,
            dnssecChainFixture.trustAnchors,
          );

          expect(wasSignedByMember).toBe(true);
        });
      });

      describe('Organisation signatures', () => {
        test('Member name should be output if attributed to user', async () => {
          const attributedMemberName = 'alice';
          const orgSigner = new OrganisationSigner(
            VERAID_DNSSEC_CHAIN,
            orgCertificate,
            attributedMemberName,
          );
          const signatureBundle = await SignatureBundle.sign(
            PLAINTEXT,
            SERVICE_OID,
            orgSigner,
            ORG_KEY_PAIR.privateKey,
            DATE_PERIOD.end,
            { startDate: DATE_PERIOD.start },
          );

          const {
            member: { user },
          } = await signatureBundle.verify(
            PLAINTEXT,
            SERVICE_OID,
            DATE_PERIOD,
            dnssecChainFixture.trustAnchors,
          );

          expect(user).toBe(attributedMemberName);
        });

        test('Member name should not be output if attributed to bot', async () => {
          const orgSigner = new OrganisationSigner(VERAID_DNSSEC_CHAIN, orgCertificate);
          const signatureBundle = await SignatureBundle.sign(
            PLAINTEXT,
            SERVICE_OID,
            orgSigner,
            ORG_KEY_PAIR.privateKey,
            DATE_PERIOD.end,
            { startDate: DATE_PERIOD.start },
          );

          const {
            member: { user },
          } = await signatureBundle.verify(
            PLAINTEXT,
            SERVICE_OID,
            DATE_PERIOD,
            dnssecChainFixture.trustAnchors,
          );

          expect(user).toBeUndefined();
        });

        test('Signature should be deemed as signed by organisation', async () => {
          const orgSigner = new OrganisationSigner(VERAID_DNSSEC_CHAIN, orgCertificate);
          const signatureBundle = await SignatureBundle.sign(
            PLAINTEXT,
            SERVICE_OID,
            orgSigner,
            ORG_KEY_PAIR.privateKey,
            DATE_PERIOD.end,
            { startDate: DATE_PERIOD.start },
          );

          const { wasSignedByMember } = await signatureBundle.verify(
            PLAINTEXT,
            SERVICE_OID,
            DATE_PERIOD,
            dnssecChainFixture.trustAnchors,
          );

          expect(wasSignedByMember).toBe(false);
        });
      });
    });
  });
});
