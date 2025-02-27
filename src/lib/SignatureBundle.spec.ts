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

import { generateMemberIdFixture } from '../testUtils/veraStubs/memberIdFixture.js';
import { serialiseMessage } from '../testUtils/dns.js';
import { arrayBufferFrom } from '../testUtils/buffers.js';
import { SERVICE_OID } from '../testUtils/veraStubs/service.js';
import { MEMBER_KEY_PAIR } from '../testUtils/veraStubs/member.js';

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

const { orgCertificateSerialised, memberCertificateSerialised, dnssecChainFixture, datePeriod } =
  await generateMemberIdFixture();
const dnssecChain = new DnssecChainSchema(
  dnssecChainFixture.responses.map(serialiseMessage).map(bufferToArray),
);

const orgCertificateSchema = AsnParser.parse(orgCertificateSerialised, CertificateSchema);
const memberCertificateSchema = AsnParser.parse(memberCertificateSerialised, CertificateSchema);

// Create a plaintext for testing
const PLAINTEXT = arrayBufferFrom('Hello world');

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
});
