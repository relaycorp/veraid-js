import { jest } from '@jest/globals';
import { RrSet, SecurityStatus } from '@relaycorp/dnssec';
import { AsnParser, AsnSerializer } from '@peculiar/asn1-schema';
import { Null } from 'asn1js';
import {
  Attribute,
  ContentInfo,
  SignedData as SignedDataSchema,
  type SignerInfo,
} from '@peculiar/asn1-cms';
import { setMilliseconds, subSeconds } from 'date-fns';
import { Attribute as PkijsAttribute } from 'pkijs';

import { generateMemberIdFixture } from '../testUtils/veraStubs/memberIdFixture.js';
import { serialiseMessage } from '../testUtils/dns.js';
import { SERVICE_OID } from '../testUtils/veraStubs/service.js';
import { MEMBER_KEY_PAIR, MEMBER_NAME } from '../testUtils/veraStubs/member.js';
import { arrayBufferFrom } from '../testUtils/buffers.js';
import {
  ORG_KEY_PAIR,
  ORG_NAME,
  VERA_RECORD,
  VERA_RECORD_TTL_OVERRIDE,
} from '../testUtils/veraStubs/organisation.js';
import { expectErrorToEqual, getPromiseRejection } from '../testUtils/errors.js';
import { MOCK_CHAIN } from '../testUtils/veraStubs/dnssec.js';

import { bufferToArray } from './utils/buffers.js';
import { serialiseMemberIdBundle } from './memberIdBundle/serialisation.js';
import { DnssecChainSchema } from './schemas/DnssecChainSchema.js';
import { SignatureBundleSchema } from './schemas/SignatureBundleSchema.js';
import { SignedData } from './utils/cms/SignedData.js';
import Certificate from './utils/x509/Certificate.js';
import { CMS_OIDS, VERA_OIDS } from './oids.js';
import { SignatureMetadataSchema } from './schemas/SignatureMetadataSchema.js';
import VeraError from './VeraError.js';
import { sign, verify } from './signature.js';
import CmsError from './utils/cms/CmsError.js';
import { generateTxtRdata } from './dns/rdataSerialisation.js';
import { MemberIdBundle } from './memberIdBundle/MemberIdBundle.js';
import { DatePeriod, type IDatePeriod } from './dates.js';
import { issueMemberCertificate } from './pki/member.js';
import { DatePeriodSchema } from './schemas/DatePeriodSchema.js';
import { derDeserialize } from './utils/asn1.js';

const PLAINTEXT = arrayBufferFrom('the plaintext');

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

const SIGNATURE_BUNDLE_SERIALISED = await sign(
  PLAINTEXT,
  SERVICE_OID,
  MEMBER_ID_BUNDLE,
  MEMBER_KEY_PAIR.privateKey,
  datePeriod.end,
  datePeriod.start,
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

describe('verify', () => {
  test('Signature bundle should be well-formed', async () => {
    const malformedSignatureBundle = arrayBufferFrom('malformed');

    await expect(async () =>
      verify(PLAINTEXT, malformedSignatureBundle, SERVICE_OID),
    ).rejects.toThrowWithMessage(VeraError, 'Signature bundle is malformed');
  });

  test('Metadata attribute should be present in signature', async () => {
    const signatureBundle = AsnParser.parse(SIGNATURE_BUNDLE_SERIALISED, SignatureBundleSchema);
    const memberCertificate = Certificate.deserialize(memberCertificateSerialised);
    const signedData = await SignedData.sign(
      PLAINTEXT,
      MEMBER_KEY_PAIR.privateKey,
      memberCertificate,
      [],
      { encapsulatePlaintext: false },
    );
    signatureBundle.signature = AsnParser.parse(signedData.serialize(), ContentInfo);
    const signatureBundleSerialised = AsnSerializer.serialize(signatureBundle);

    await expect(async () =>
      verify(
        PLAINTEXT,
        signatureBundleSerialised,
        SERVICE_OID,
        datePeriod,
        dnssecChainFixture.trustAnchors,
      ),
    ).rejects.toThrowWithMessage(VeraError, 'Signature metadata is missing');
  });

  test('Metadata attribute should be well-formed', async () => {
    const signatureBundle = AsnParser.parse(SIGNATURE_BUNDLE_SERIALISED, SignatureBundleSchema);
    const memberCertificate = Certificate.deserialize(memberCertificateSerialised);
    const attribute = new PkijsAttribute({
      type: VERA_OIDS.SIGNATURE_METADATA_ATTR,
      values: [new Null()],
    });
    const signedData = await SignedData.sign(
      PLAINTEXT,
      MEMBER_KEY_PAIR.privateKey,
      memberCertificate,
      [],
      {
        encapsulatePlaintext: false,
        extraSignedAttrs: [attribute],
      },
    );
    signatureBundle.signature = AsnParser.parse(signedData.serialize(), ContentInfo);
    const signatureBundleSerialised = AsnSerializer.serialize(signatureBundle);

    await expect(async () =>
      verify(
        PLAINTEXT,
        signatureBundleSerialised,
        SERVICE_OID,
        datePeriod,
        dnssecChainFixture.trustAnchors,
      ),
    ).rejects.toThrowWithMessage(VeraError, 'Signature metadata is malformed');
  });

  test('Metadata should contain valid validity period', async () => {
    const signatureBundle = AsnParser.parse(SIGNATURE_BUNDLE_SERIALISED, SignatureBundleSchema);
    const memberCertificate = Certificate.deserialize(memberCertificateSerialised);
    const metadata = new SignatureMetadataSchema();
    metadata.serviceOid = SERVICE_OID;
    metadata.validityPeriod = new DatePeriodSchema();
    metadata.validityPeriod.start = datePeriod.start;
    metadata.validityPeriod.end = subSeconds(datePeriod.start, 1); // Invalid
    const attribute = new PkijsAttribute({
      type: VERA_OIDS.SIGNATURE_METADATA_ATTR,
      values: [derDeserialize(AsnSerializer.serialize(metadata))],
    });
    const signedData = await SignedData.sign(
      PLAINTEXT,
      MEMBER_KEY_PAIR.privateKey,
      memberCertificate,
      [],
      {
        encapsulatePlaintext: false,
        extraSignedAttrs: [attribute],
      },
    );
    signatureBundle.signature = AsnParser.parse(signedData.serialize(), ContentInfo);
    const signatureBundleSerialised = AsnSerializer.serialize(signatureBundle);

    await expect(async () =>
      verify(
        PLAINTEXT,
        signatureBundleSerialised,
        SERVICE_OID,
        datePeriod,
        dnssecChainFixture.trustAnchors,
      ),
    ).rejects.toThrowWithMessage(VeraError, 'Signature validity period ends before it starts');
  });

  test('Signature should correspond to specified plaintext', async () => {
    const differentPlaintext = bufferToArray(Buffer.from(PLAINTEXT, 1));

    const error = await getPromiseRejection(
      async () =>
        verify(
          differentPlaintext,
          SIGNATURE_BUNDLE_SERIALISED,
          SERVICE_OID,
          datePeriod,
          dnssecChainFixture.trustAnchors,
        ),
      VeraError,
    );

    expectErrorToEqual(
      error,
      new VeraError('Signature is invalid', { cause: expect.any(CmsError) }),
    );
  });

  test('Member id bundle should be valid', async () => {
    const invalidMemberIdBundle = serialiseMemberIdBundle(
      memberCertificateSerialised,
      memberCertificateSerialised, // Invalid
      DNSSEC_CHAIN_SERIALISED,
    );
    const signatureBundle = await sign(
      PLAINTEXT,
      SERVICE_OID,
      invalidMemberIdBundle,
      MEMBER_KEY_PAIR.privateKey,
      datePeriod.end,
      datePeriod.start,
    );

    const error = await getPromiseRejection(
      async () =>
        verify(
          PLAINTEXT,
          signatureBundle,
          SERVICE_OID,
          datePeriod,
          dnssecChainFixture.trustAnchors,
        ),
      VeraError,
    );

    expectErrorToEqual(
      error,
      new VeraError('Member id bundle is invalid', { cause: expect.any(VeraError) }),
    );
  });

  describe('Service OID', () => {
    test('Service OID should match that of the signature metadata', async () => {
      const differentServiceOid = `${SERVICE_OID}.1`;

      await expect(async () =>
        verify(
          PLAINTEXT,
          SIGNATURE_BUNDLE_SERIALISED,
          differentServiceOid,
          datePeriod,
          dnssecChainFixture.trustAnchors,
        ),
      ).rejects.toThrowWithMessage(
        VeraError,
        `Signature is bound to a different service (${SERVICE_OID})`,
      );
    });

    test('Service OID in signature should match that of member id bundle', async () => {
      const bundleVerifySpy = jest.spyOn(MemberIdBundle.prototype, 'verify');
      const differentServiceOid = `${SERVICE_OID}.1`;
      const record = VERA_RECORD.shallowCopy({
        data: await generateTxtRdata(
          ORG_KEY_PAIR.publicKey,
          VERA_RECORD_TTL_OVERRIDE,
          differentServiceOid,
        ),
      });
      const rrset = RrSet.init(record.makeQuestion(), [record]);
      const { responses, trustAnchors } = MOCK_CHAIN.generateFixture(
        rrset,
        SecurityStatus.SECURE,
        datePeriod,
      );
      const responsesSerialised = responses.map(serialiseMessage).map(arrayBufferFrom);
      const signatureBundle = AsnParser.parse(SIGNATURE_BUNDLE_SERIALISED, SignatureBundleSchema);
      signatureBundle.dnssecChain = new DnssecChainSchema(responsesSerialised);
      const signatureBundleSerialised = AsnSerializer.serialize(signatureBundle);

      await expect(async () =>
        verify(PLAINTEXT, signatureBundleSerialised, SERVICE_OID, datePeriod, trustAnchors),
      ).rejects.toThrowWithMessage(VeraError, 'Member id bundle is invalid');
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

      await verify(
        PLAINTEXT,
        SIGNATURE_BUNDLE_SERIALISED,
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

      await verify(
        PLAINTEXT,
        SIGNATURE_BUNDLE_SERIALISED,
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
      const invalidExpiryDate = subSeconds(datePeriod.start, 1);
      const period: IDatePeriod = { start: datePeriod.start, end: invalidExpiryDate };

      await expect(async () =>
        verify(
          PLAINTEXT,
          SIGNATURE_BUNDLE_SERIALISED,
          SERVICE_OID,
          period,
          dnssecChainFixture.trustAnchors,
        ),
      ).rejects.toThrowWithMessage(
        VeraError,
        'Verification expiry date cannot be before start date',
      );
    });

    test('Period should overlap with that of signature', async () => {
      const signatureBundleSerialised = await sign(
        PLAINTEXT,
        SERVICE_OID,
        MEMBER_ID_BUNDLE,
        MEMBER_KEY_PAIR.privateKey,
        subSeconds(datePeriod.start, 1),
        subSeconds(datePeriod.start, 2),
      );

      await expect(async () =>
        verify(
          PLAINTEXT,
          signatureBundleSerialised,
          SERVICE_OID,
          datePeriod,
          dnssecChainFixture.trustAnchors,
        ),
      ).rejects.toThrowWithMessage(
        VeraError,
        'Signature period does not overlap with required period',
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
      const memberIdBundle = serialiseMemberIdBundle(
        otherMemberCertificate,
        orgCertificateSerialised,
        DNSSEC_CHAIN_SERIALISED,
      );
      const signatureBundleSerialised = await sign(
        PLAINTEXT,
        SERVICE_OID,
        memberIdBundle,
        MEMBER_KEY_PAIR.privateKey,
        datePeriod.end,
        datePeriod.start,
      );

      await expect(async () =>
        verify(
          PLAINTEXT,
          signatureBundleSerialised,
          SERVICE_OID,
          verificationPeriod,
          dnssecChainFixture.trustAnchors,
        ),
      ).rejects.toThrowWithMessage(VeraError, 'Member id bundle is invalid');
      expect(bundleVerifySpy).toHaveBeenCalledWith(
        expect.anything(),
        datePeriod.intersect(verificationPeriod),
        expect.anything(),
      );
    });
  });

  describe('Valid result', () => {
    test('Organisation name should be output', async () => {
      const { organisation } = await verify(
        PLAINTEXT,
        SIGNATURE_BUNDLE_SERIALISED,
        SERVICE_OID,
        datePeriod,
        dnssecChainFixture.trustAnchors,
      );

      expect(organisation).toStrictEqual(ORG_NAME);
    });

    test('User name should be output if member is a user', async () => {
      const { user } = await verify(
        PLAINTEXT,
        SIGNATURE_BUNDLE_SERIALISED,
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
      const memberIdBundle = serialiseMemberIdBundle(
        botCertificate,
        orgCertificateSerialised,
        DNSSEC_CHAIN_SERIALISED,
      );
      const signatureBundleSerialised = await sign(
        PLAINTEXT,
        SERVICE_OID,
        memberIdBundle,
        MEMBER_KEY_PAIR.privateKey,
        datePeriod.end,
        datePeriod.start,
      );

      const { user } = await verify(
        PLAINTEXT,
        signatureBundleSerialised,
        SERVICE_OID,
        datePeriod,
        dnssecChainFixture.trustAnchors,
      );

      expect(user).toBeUndefined();
    });
  });
});
