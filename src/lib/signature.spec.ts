import { jest } from '@jest/globals';
import { type Message, RrSet, SecurityStatus } from '@relaycorp/dnssec';
import { AsnParser, AsnSerializer } from '@peculiar/asn1-schema';
import { Null } from 'asn1js';
import { ContentInfo } from '@peculiar/asn1-cms';
import { subSeconds } from 'date-fns';
import { Attribute as PkijsAttribute } from 'pkijs';

import { generateMemberIdFixture } from '../testUtils/veraStubs/memberIdFixture.js';
import { serialiseMessage } from '../testUtils/dns.js';
import { SERVICE_OID } from '../testUtils/veraStubs/service.js';
import { MEMBER_KEY_PAIR, MEMBER_NAME } from '../testUtils/veraStubs/member.js';
import { arrayBufferFrom } from '../testUtils/buffers.js';
import {
  ORG_KEY_PAIR,
  ORG_NAME,
  VERAID_RECORD,
  VERAID_RECORD_TTL_OVERRIDE,
} from '../testUtils/veraStubs/organisation.js';
import { expectErrorToEqual, getPromiseRejection } from '../testUtils/errors.js';
import { MOCK_CHAIN } from '../testUtils/veraStubs/dnssec.js';

import { bufferToArray } from './utils/buffers.js';
import { serialiseMemberIdBundle } from './memberIdBundle/serialisation.js';
import { DnssecChainSchema } from './schemas/DnssecChainSchema.js';
import { SignatureBundleSchema } from './schemas/SignatureBundleSchema.js';
import { SignedData } from './utils/cms/SignedData.js';
import Certificate from './utils/x509/Certificate.js';
import { VERAID_OIDS } from './oids.js';
import { SignatureMetadataSchema } from './schemas/SignatureMetadataSchema.js';
import VeraidError from './VeraidError.js';
import { verify } from './signature.js';
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

// Create a signature bundle for testing
const bundleInstance = MemberIdBundle.deserialise(MEMBER_ID_BUNDLE);
const SIGNATURE_BUNDLE_SERIALISED = await bundleInstance.sign(
  PLAINTEXT,
  SERVICE_OID,
  MEMBER_KEY_PAIR.privateKey,
  datePeriod.end,
  { startDate: datePeriod.start },
);

describe('verify', () => {
  interface SignatureBundleAttributeSet {
    readonly dnssecResponses: readonly Message[];
    readonly signedData: SignedData;
  }

  function replaceSignatureAttribute(
    signatureBundleSerialised: ArrayBuffer,
    attributes: Partial<SignatureBundleAttributeSet>,
  ): ArrayBuffer {
    const signatureBundle = AsnParser.parse(signatureBundleSerialised, SignatureBundleSchema);

    if (attributes.dnssecResponses) {
      const responsesSerialised = attributes.dnssecResponses
        .map(serialiseMessage)
        .map(arrayBufferFrom);
      signatureBundle.dnssecChain = new DnssecChainSchema(responsesSerialised);
    }

    if (attributes.signedData) {
      signatureBundle.signature = AsnParser.parse(attributes.signedData.serialize(), ContentInfo);
    }

    return AsnSerializer.serialize(signatureBundle);
  }

  test('Signature bundle should be well-formed', async () => {
    const malformedSignatureBundle = arrayBufferFrom('malformed');

    await expect(async () =>
      verify(PLAINTEXT, malformedSignatureBundle, SERVICE_OID),
    ).rejects.toThrowWithMessage(VeraidError, 'Signature bundle is malformed');
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
    ).rejects.toThrowWithMessage(VeraidError, 'Signature metadata is missing');
  });

  test('Metadata attribute should be well-formed', async () => {
    const memberCertificate = Certificate.deserialize(memberCertificateSerialised);
    const attribute = new PkijsAttribute({
      type: VERAID_OIDS.SIGNATURE_METADATA_ATTR,
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
    const signatureBundleSerialised = replaceSignatureAttribute(SIGNATURE_BUNDLE_SERIALISED, {
      signedData,
    });

    await expect(async () =>
      verify(
        PLAINTEXT,
        signatureBundleSerialised,
        SERVICE_OID,
        datePeriod,
        dnssecChainFixture.trustAnchors,
      ),
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
      PLAINTEXT,
      MEMBER_KEY_PAIR.privateKey,
      memberCertificate,
      [],
      {
        encapsulatePlaintext: false,
        extraSignedAttrs: [attribute],
      },
    );
    const signatureBundleSerialised = replaceSignatureAttribute(SIGNATURE_BUNDLE_SERIALISED, {
      signedData,
    });

    await expect(async () =>
      verify(
        PLAINTEXT,
        signatureBundleSerialised,
        SERVICE_OID,
        datePeriod,
        dnssecChainFixture.trustAnchors,
      ),
    ).rejects.toThrowWithMessage(VeraidError, 'Signature validity period ends before it starts');
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
    const signatureBundle = await invalidBundle.sign(
      PLAINTEXT,
      SERVICE_OID,
      MEMBER_KEY_PAIR.privateKey,
      datePeriod.end,
      { startDate: datePeriod.start },
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

      await expect(async () =>
        verify(
          PLAINTEXT,
          SIGNATURE_BUNDLE_SERIALISED,
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

      await expect(async () =>
        verify(PLAINTEXT, signatureBundleSerialised, SERVICE_OID, datePeriod, trustAnchors),
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
      const signatureBundleSerialised = await testBundle.sign(
        PLAINTEXT,
        SERVICE_OID,
        MEMBER_KEY_PAIR.privateKey,
        signaturePeriod.end,
        { startDate: signaturePeriod.start },
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
      const signatureBundleSerialised = await testBundle.sign(
        PLAINTEXT,
        SERVICE_OID,
        MEMBER_KEY_PAIR.privateKey,
        datePeriod.end,
        { startDate: datePeriod.start },
      );

      await expect(async () =>
        verify(
          PLAINTEXT,
          signatureBundleSerialised,
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
      const signatureBundleSerialised = await testBundle.sign(
        PLAINTEXT,
        SERVICE_OID,
        MEMBER_KEY_PAIR.privateKey,
        datePeriod.end,
        { shouldEncapsulatePlaintext: true },
      );

      const error = await getPromiseRejection(
        async () =>
          verify(
            PLAINTEXT,
            signatureBundleSerialised,
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
      const signatureBundleSerialised = await testBundle.sign(
        PLAINTEXT,
        SERVICE_OID,
        MEMBER_KEY_PAIR.privateKey,
        datePeriod.end,
        { shouldEncapsulatePlaintext: false },
      );

      const error = await getPromiseRejection(
        async () =>
          verify(
            undefined,
            signatureBundleSerialised,
            SERVICE_OID,
            datePeriod,
            dnssecChainFixture.trustAnchors,
          ),
        VeraidError,
      );

      expect(error.cause).toBeInstanceOf(CmsError);
    });
  });

  describe('Valid result', () => {
    test('Plaintext should be taken from bundle if attached', async () => {
      const testBundle = MemberIdBundle.deserialise(MEMBER_ID_BUNDLE);
      const signatureBundleSerialised = await testBundle.sign(
        PLAINTEXT,
        SERVICE_OID,
        MEMBER_KEY_PAIR.privateKey,
        datePeriod.end,
        { shouldEncapsulatePlaintext: true },
      );

      const { plaintext } = await verify(
        undefined,
        signatureBundleSerialised,
        SERVICE_OID,
        datePeriod,
        dnssecChainFixture.trustAnchors,
      );

      expect(Buffer.from(plaintext)).toMatchObject(Buffer.from(PLAINTEXT));
    });

    test('Plaintext should be taken from parameter if detached', async () => {
      const { plaintext } = await verify(
        PLAINTEXT,
        SIGNATURE_BUNDLE_SERIALISED,
        SERVICE_OID,
        datePeriod,
        dnssecChainFixture.trustAnchors,
      );

      expect(Buffer.from(plaintext)).toMatchObject(Buffer.from(PLAINTEXT));
    });

    test('Organisation name should be output', async () => {
      const {
        member: { organisation },
      } = await verify(
        PLAINTEXT,
        SIGNATURE_BUNDLE_SERIALISED,
        SERVICE_OID,
        datePeriod,
        dnssecChainFixture.trustAnchors,
      );

      expect(organisation).toStrictEqual(ORG_NAME);
    });

    test('User name should be output if member is a user', async () => {
      const {
        member: { user },
      } = await verify(
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
      const botMemberIdBundle = serialiseMemberIdBundle(
        botCertificate,
        orgCertificateSerialised,
        DNSSEC_CHAIN_SERIALISED,
      );
      const botBundle = MemberIdBundle.deserialise(botMemberIdBundle);
      const signatureBundleSerialised = await botBundle.sign(
        PLAINTEXT,
        SERVICE_OID,
        MEMBER_KEY_PAIR.privateKey,
        datePeriod.end,
        { startDate: datePeriod.start },
      );

      const {
        member: { user },
      } = await verify(
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
