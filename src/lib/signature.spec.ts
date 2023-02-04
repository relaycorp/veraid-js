import { AsnParser, AsnSerializer } from '@peculiar/asn1-schema';
import {
  Attribute,
  type SignerInfo,
  SignedData as SignedDataSchema,
  type ContentInfo,
} from '@peculiar/asn1-cms';
import { setMilliseconds, subSeconds } from 'date-fns';

import { generateMemberIdFixture } from '../testUtils/veraStubs/memberIdFixture.js';
import { serialiseMessage } from '../testUtils/dns.js';
import { SERVICE_OID } from '../testUtils/veraStubs/service.js';
import { MEMBER_KEY_PAIR } from '../testUtils/veraStubs/member.js';
import { arrayBufferFrom } from '../testUtils/buffers.js';

import { bufferToArray } from './utils/buffers.js';
import { serialiseMemberIdBundle } from './memberIdBundle/serialisation.js';
import { DnssecChainSchema } from './schemas/DnssecChainSchema.js';
import { SignatureBundleSchema } from './schemas/SignatureBundleSchema.js';
import { SignedData } from './utils/cms/SignedData.js';
import Certificate from './utils/x509/Certificate.js';
import { CMS_OIDS, VERA_OIDS } from './oids.js';
import { SignatureMetadataSchema } from './schemas/SignatureMetadataSchema.js';
import VeraError from './VeraError.js';
import { sign } from './signature.js';

const PLAINTEXT = Buffer.from('the plaintext');

const { orgCertificateSerialised, memberCertificateSerialised, dnssecChainFixture, datePeriod } =
  await generateMemberIdFixture();

const DNSSEC_CHAIN_SERIALISED = AsnSerializer.serialize(
  new DnssecChainSchema(dnssecChainFixture.responses.map(serialiseMessage).map(bufferToArray)),
);
const MEMBER_ID_BUNDLE = serialiseMemberIdBundle(
  memberCertificateSerialised,
  orgCertificateSerialised,
  DNSSEC_CHAIN_SERIALISED,
);

describe('sign', () => {
  test('Malformed member Id bundle should be refused', async () => {
    const malformedBundle = arrayBufferFrom('malformed');

    await expect(async () =>
      sign(PLAINTEXT, SERVICE_OID, malformedBundle, MEMBER_KEY_PAIR.privateKey, datePeriod.end),
    ).rejects.toThrowWithMessage(VeraError, 'Member id bundle is malformed');
  });

  test('DNSSEC chain should be attached', async () => {
    const signatureSerialised = await sign(
      PLAINTEXT,
      SERVICE_OID,
      MEMBER_ID_BUNDLE,
      MEMBER_KEY_PAIR.privateKey,
      datePeriod.end,
    );

    const { dnssecChain } = AsnParser.parse(signatureSerialised, SignatureBundleSchema);
    expect(Buffer.from(AsnSerializer.serialize(dnssecChain))).toStrictEqual(
      Buffer.from(DNSSEC_CHAIN_SERIALISED),
    );
  });

  test('Organisation certificate should be attached', async () => {
    const signatureSerialised = await sign(
      PLAINTEXT,
      SERVICE_OID,
      MEMBER_ID_BUNDLE,
      MEMBER_KEY_PAIR.privateKey,
      datePeriod.end,
    );

    const { organisationCertificate } = AsnParser.parse(signatureSerialised, SignatureBundleSchema);
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
      const signatureSerialised = await sign(
        PLAINTEXT,
        SERVICE_OID,
        MEMBER_ID_BUNDLE,
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
      const signatureSerialised = await sign(
        PLAINTEXT,
        SERVICE_OID,
        MEMBER_ID_BUNDLE,
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

    test('Plaintext should be detached', async () => {
      const signatureSerialised = await sign(
        PLAINTEXT,
        SERVICE_OID,
        MEMBER_ID_BUNDLE,
        MEMBER_KEY_PAIR.privateKey,
        datePeriod.end,
      );

      const { signature } = AsnParser.parse(signatureSerialised, SignatureBundleSchema);
      const { encapContentInfo } = getSignedData(signature);
      expect(encapContentInfo.eContent).toBeUndefined();
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
          VERA_OIDS.SIGNATURE_METADATA_ATTR,
        );
        expect(attributeValues).toHaveLength(1);
        return AsnParser.parse(attributeValues[0], SignatureMetadataSchema);
      }

      test('Service OID should be attached', async () => {
        const signatureSerialised = await sign(
          PLAINTEXT,
          SERVICE_OID,
          MEMBER_ID_BUNDLE,
          MEMBER_KEY_PAIR.privateKey,
          datePeriod.end,
        );

        const { signature } = AsnParser.parse(signatureSerialised, SignatureBundleSchema);
        const { serviceOid } = getSignatureMetadata(signature);
        expect(serviceOid).toStrictEqual(SERVICE_OID);
      });

      test('Expiry date should be attached', async () => {
        const signatureSerialised = await sign(
          PLAINTEXT,
          SERVICE_OID,
          MEMBER_ID_BUNDLE,
          MEMBER_KEY_PAIR.privateKey,
          datePeriod.end,
        );

        const { signature } = AsnParser.parse(signatureSerialised, SignatureBundleSchema);
        const { validityPeriod } = getSignatureMetadata(signature);
        expect(validityPeriod.end).toStrictEqual(datePeriod.end);
      });

      test('Start date should default to the current time', async () => {
        const beforeSignatureDate = setMilliseconds(new Date(), 0);
        const signatureSerialised = await sign(
          PLAINTEXT,
          SERVICE_OID,
          MEMBER_ID_BUNDLE,
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
        const signatureSerialised = await sign(
          PLAINTEXT,
          SERVICE_OID,
          MEMBER_ID_BUNDLE,
          MEMBER_KEY_PAIR.privateKey,
          datePeriod.end,
          startDate,
        );

        const { signature } = AsnParser.parse(signatureSerialised, SignatureBundleSchema);
        const { validityPeriod } = getSignatureMetadata(signature);
        expect(validityPeriod.start).toStrictEqual(startDate);
      });

      test('Start date after expiry date should be refused', async () => {
        const invalidExpiryDate = subSeconds(datePeriod.start, 1);

        await expect(async () =>
          sign(
            PLAINTEXT,
            SERVICE_OID,
            MEMBER_ID_BUNDLE,
            MEMBER_KEY_PAIR.privateKey,
            invalidExpiryDate,
            datePeriod.start,
          ),
        ).rejects.toThrowWithMessage(VeraError, 'Signature start date cannot be after expiry date');
      });
    });
  });
});
