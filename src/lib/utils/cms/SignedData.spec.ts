import { jest } from '@jest/globals';
import {
  type IBerConvertible,
  Integer,
  type ObjectIdentifier,
  OctetString,
  Sequence,
} from 'asn1js';
import {
  Attribute,
  type Certificate as PkijsCertificate,
  EncapsulatedContentInfo,
  IssuerAndSerialNumber,
  RelativeDistinguishedNames,
  SignedAndUnsignedAttributes,
  SignedData as PkijsSignedData,
  SignerInfo,
} from 'pkijs';

import { CMS_OIDS } from '../../oids.js';
import { type HashingAlgorithm } from '../algorithms.js';
import type Certificate from '../x509/Certificate.js';
import { asn1Serialise, expectAsn1ValuesToBeEqual } from '../../../testUtils/asn1.js';
import { expectFunctionToThrowError } from '../../../testUtils/errors.js';
import { MockRsaPssProvider } from '../../../testUtils/webcrypto/MockRsaPssProvider.js';
import { pkijsSerialise, serializeContentInfo } from '../../../testUtils/cms.js';
import { arrayBufferFrom } from '../../../testUtils/buffers.js';
import { calculateDigest } from '../../../testUtils/crypto.js';
import { generateStubCert } from '../../../testUtils/pki.js';
import { expectPkijsValuesToBeEqual } from '../../../testUtils/pkijs.js';
import { RsaPssPrivateKey } from '../keys/RsaPssPrivateKey.js';
import { generateRsaKeyPair } from '../keys/generation.js';
import { MEMBER_KEY_PAIR } from '../../../testUtils/veraStubs/member.js';

import { deserializeContentInfo } from './utils.js';
import { SignedData } from './SignedData.js';
import CmsError from './CmsError.js';

const plaintext = arrayBufferFrom('Winter is coming');

let certificate: Certificate;
beforeAll(async () => {
  certificate = await generateStubCert({
    issuerPrivateKey: MEMBER_KEY_PAIR.privateKey,
    subjectPublicKey: MEMBER_KEY_PAIR.publicKey,
  });
});

afterEach(() => {
  jest.restoreAllMocks();
});

describe('sign', () => {
  function getSignerInfoAttribute(signerInfo: SignerInfo, attributeOid: string): Attribute {
    const { attributes } = signerInfo.signedAttrs!;
    const matchingAttributes = attributes.filter((attribute) => attribute.type === attributeOid);
    expect(matchingAttributes).toHaveLength(1);
    return matchingAttributes[0];
  }

  test('SignedData version should be 1', async () => {
    const signedData = await SignedData.sign(plaintext, MEMBER_KEY_PAIR.privateKey, certificate);

    expect(signedData.pkijsSignedData).toHaveProperty('version', 1);
  });

  test('Crypto in private key should be used if set', async () => {
    const provider = new MockRsaPssProvider();
    const privateKey = new RsaPssPrivateKey('SHA-256', provider);

    await expect(SignedData.sign(plaintext, privateKey, certificate)).toResolve();

    expect(provider.onSign).toHaveBeenCalledWith(expect.anything(), privateKey, expect.anything());
  });

  describe('SignerInfo', () => {
    test('There should only be one SignerInfo', async () => {
      const signedData = await SignedData.sign(plaintext, MEMBER_KEY_PAIR.privateKey, certificate);

      expect(signedData.pkijsSignedData.signerInfos).toHaveLength(1);
      expect(signedData.pkijsSignedData.signerInfos[0]).toBeInstanceOf(SignerInfo);
    });

    test('Version should be 1', async () => {
      const signedData = await SignedData.sign(plaintext, MEMBER_KEY_PAIR.privateKey, certificate);

      expect(signedData.pkijsSignedData.signerInfos[0]).toHaveProperty('version', 1);
    });

    test('SignerIdentifier should be IssuerAndSerialNumber', async () => {
      const signedData = await SignedData.sign(plaintext, MEMBER_KEY_PAIR.privateKey, certificate);

      const [signerInfo] = signedData.pkijsSignedData.signerInfos;
      expect(signerInfo.sid).toBeInstanceOf(IssuerAndSerialNumber);
      expectPkijsValuesToBeEqual(
        (signerInfo.sid as IssuerAndSerialNumber).issuer,
        certificate.pkijsCertificate.issuer,
      );
      expectAsn1ValuesToBeEqual(
        (signerInfo.sid as IssuerAndSerialNumber).serialNumber,
        certificate.pkijsCertificate.serialNumber,
      );
    });

    describe('SignedAttributes', () => {
      test('Signed attributes should be present', async () => {
        const signedData = await SignedData.sign(
          plaintext,
          MEMBER_KEY_PAIR.privateKey,
          certificate,
        );

        const [signerInfo] = signedData.pkijsSignedData.signerInfos;
        expect(signerInfo.signedAttrs).toBeInstanceOf(SignedAndUnsignedAttributes);
        expect(signerInfo.signedAttrs).toHaveProperty('type', 0);
      });

      test('Content type attribute should be set to CMS Data', async () => {
        const signedData = await SignedData.sign(
          plaintext,
          MEMBER_KEY_PAIR.privateKey,
          certificate,
        );

        const contentTypeAttribute = getSignerInfoAttribute(
          signedData.pkijsSignedData.signerInfos[0],
          CMS_OIDS.ATTR_CONTENT_TYPE,
        );
        expect(contentTypeAttribute.values).toHaveLength(1);
        expect(
          (contentTypeAttribute.values[0] as ObjectIdentifier).valueBlock.toString(),
        ).toStrictEqual(CMS_OIDS.DATA);
      });

      test('Plaintext digest should be present', async () => {
        const signedData = await SignedData.sign(
          plaintext,
          MEMBER_KEY_PAIR.privateKey,
          certificate,
        );

        const digestAttribute = getSignerInfoAttribute(
          signedData.pkijsSignedData.signerInfos[0],
          CMS_OIDS.ATTR_DIGEST,
        );
        expect(digestAttribute.values).toHaveLength(1);
        const digest = (digestAttribute.values[0] as OctetString).valueBlock.valueHexView;
        expect(Buffer.from(digest)).toStrictEqual(calculateDigest('sha256', plaintext));
      });
    });
  });

  describe('Attached certificates', () => {
    test('The signer certificate should be attached', async () => {
      const signedData = await SignedData.sign(plaintext, MEMBER_KEY_PAIR.privateKey, certificate);

      expect(signedData.pkijsSignedData.certificates).toHaveLength(1);
      expectPkijsValuesToBeEqual(
        (signedData.pkijsSignedData.certificates as readonly PkijsCertificate[])[0],
        certificate.pkijsCertificate,
      );
    });

    test('CA certificate chain should optionally be attached', async () => {
      const rootCaCertificate = await generateStubCert();
      const intermediateCaCertificate = await generateStubCert();
      const signedData = await SignedData.sign(plaintext, MEMBER_KEY_PAIR.privateKey, certificate, [
        intermediateCaCertificate,
        rootCaCertificate,
      ]);

      expect(signedData.pkijsSignedData.certificates).toHaveLength(3);
      const attachedCertificates = signedData.pkijsSignedData
        .certificates as readonly PkijsCertificate[];
      expectPkijsValuesToBeEqual(attachedCertificates[0], certificate.pkijsCertificate);
      expectPkijsValuesToBeEqual(
        attachedCertificates[1],
        intermediateCaCertificate.pkijsCertificate,
      );
      expectPkijsValuesToBeEqual(attachedCertificates[2], rootCaCertificate.pkijsCertificate);
    });
  });

  describe('Extra signed attributes', () => {
    test('Extra attributes should be optional', async () => {
      const signedData = await SignedData.sign(plaintext, MEMBER_KEY_PAIR.privateKey, certificate);

      const { attributes } = signedData.pkijsSignedData.signerInfos[0].signedAttrs!;
      const attributeOids = attributes.map((attribute) => attribute.type);
      expect(attributeOids).toHaveLength(2);
      expect(attributeOids).toContainEqual(CMS_OIDS.ATTR_CONTENT_TYPE);
      expect(attributeOids).toContainEqual(CMS_OIDS.ATTR_DIGEST);
    });

    test('Any extra attributes should be honored', async () => {
      const attribute = new Attribute({
        type: '1.2.3.4.5',
        values: [new OctetString({ valueHex: arrayBufferFrom('foo') })],
      });
      const signedData = await SignedData.sign(
        plaintext,
        MEMBER_KEY_PAIR.privateKey,
        certificate,
        [],
        { extraSignedAttrs: [attribute] },
      );

      const attachedAttribute = getSignerInfoAttribute(
        signedData.pkijsSignedData.signerInfos[0],
        attribute.type,
      );
      expect(
        Buffer.from((attachedAttribute.values[0] as OctetString).valueBlock.valueHexView),
      ).toStrictEqual(Buffer.from((attribute.values[0] as OctetString).valueBlock.valueHexView));
    });
  });

  describe('Hashing', () => {
    test('SHA-256 should be used by default', async () => {
      const signedData = await SignedData.sign(plaintext, MEMBER_KEY_PAIR.privateKey, certificate);

      const digestAttribute = getSignerInfoAttribute(
        signedData.pkijsSignedData.signerInfos[0],
        CMS_OIDS.ATTR_DIGEST,
      );
      expect(
        Buffer.from((digestAttribute.values[0] as OctetString).valueBlock.valueHexView),
      ).toStrictEqual(calculateDigest('sha256', plaintext));
    });

    test.each(['SHA-384', 'SHA-512'] as readonly HashingAlgorithm[])(
      '%s should be supported',
      async (hashingAlgorithmName) => {
        const signedData = await SignedData.sign(
          plaintext,
          MEMBER_KEY_PAIR.privateKey,
          certificate,
          [],
          {
            hashingAlgorithmName,
          },
        );

        const digestAttribute = getSignerInfoAttribute(
          signedData.pkijsSignedData.signerInfos[0],
          CMS_OIDS.ATTR_DIGEST,
        );
        const algorithmNameNodejs = hashingAlgorithmName.toLowerCase().replace('-', '');
        const digest = (digestAttribute.values[0] as OctetString).valueBlock.valueHexView;
        expect(Buffer.from(digest)).toStrictEqual(calculateDigest(algorithmNameNodejs, plaintext));
      },
    );

    test('SHA-1 should not be a valid hashing function', async () => {
      await expect(async () =>
        SignedData.sign(plaintext, MEMBER_KEY_PAIR.privateKey, certificate, [], {
          hashingAlgorithmName: 'SHA-1' as HashingAlgorithm,
        }),
      ).rejects.toThrowWithMessage(CmsError, 'SHA-1 is unsupported');
    });
  });

  describe('Plaintext', () => {
    test('Plaintext should be encapsulated by default', async () => {
      const signedData = await SignedData.sign(plaintext, MEMBER_KEY_PAIR.privateKey, certificate);

      const { encapContentInfo } = signedData.pkijsSignedData;
      expect(encapContentInfo).toBeInstanceOf(EncapsulatedContentInfo);
      expect(encapContentInfo.eContentType).toBe(CMS_OIDS.DATA);
      expect(encapContentInfo.eContent).toBeInstanceOf(OctetString);
      const plaintextOctetString = encapContentInfo.eContent!.valueBlock.value[0] as OctetString;
      expect(Buffer.from(plaintext)).toStrictEqual(
        Buffer.from(plaintextOctetString.valueBlock.valueHexView.slice().buffer),
      );
    });

    test('Content should not be encapsulated if requested', async () => {
      const signedData = await SignedData.sign(
        plaintext,
        MEMBER_KEY_PAIR.privateKey,
        certificate,
        undefined,
        { encapsulatePlaintext: false },
      );

      const { encapContentInfo } = signedData.pkijsSignedData;
      expect(encapContentInfo).toBeInstanceOf(EncapsulatedContentInfo);
      expect(encapContentInfo.eContentType).toBe(CMS_OIDS.DATA);
      expect(encapContentInfo.eContent).toBeUndefined();
    });
  });
});

describe('serialize', () => {
  test('SignedData value should be wrapped in ContentInfo', async () => {
    const signedData = await SignedData.sign(plaintext, MEMBER_KEY_PAIR.privateKey, certificate);

    const signedDataSerialized = signedData.serialize();

    const contentInfo = deserializeContentInfo(signedDataSerialized);
    expect(asn1Serialise(contentInfo.content as IBerConvertible)).toStrictEqual(
      pkijsSerialise(signedData.pkijsSignedData),
    );
  });

  test('ContentInfo OID should match that of SignedData values', async () => {
    const signedData = await SignedData.sign(plaintext, MEMBER_KEY_PAIR.privateKey, certificate);

    const signedDataSerialized = signedData.serialize();

    const contentInfo = deserializeContentInfo(signedDataSerialized);
    expect(contentInfo.contentType).toStrictEqual(CMS_OIDS.SIGNED_DATA);
  });
});

describe('deserialize', () => {
  test('A non-DER-encoded value should be refused', () => {
    const invalidSignature = arrayBufferFrom('nope.jpeg');
    expectFunctionToThrowError(
      () => SignedData.deserialize(invalidSignature),
      new CmsError('Could not deserialize CMS ContentInfo', {
        cause: expect.objectContaining({ message: 'Value is not DER-encoded' }),
      }),
    );
  });

  test('ContentInfo wrapper should be required', () => {
    const invalidSignature = new Sequence().toBER(false);
    expectFunctionToThrowError(
      () => SignedData.deserialize(invalidSignature),
      new CmsError('Could not deserialize CMS ContentInfo', {
        cause: expect.objectContaining({
          message: "Object's schema was not verified against input data for ContentInfo",
        }),
      }),
    );
  });

  test('Malformed SignedData values should be refused', () => {
    const invalidSignature = serializeContentInfo(new Sequence(), '1.2.3.4');
    expectFunctionToThrowError(
      () => SignedData.deserialize(invalidSignature),
      new CmsError('SignedData value is malformed', { cause: expect.anything() }),
    );
  });

  test('Well-formed SignedData values should be deserialized', async () => {
    const signedData = await SignedData.sign(plaintext, MEMBER_KEY_PAIR.privateKey, certificate);
    const signedDataSerialized = signedData.serialize();

    const signedDataDeserialized = SignedData.deserialize(signedDataSerialized);

    expect(signedDataDeserialized.serialize()).toStrictEqual(signedData.serialize());
  });
});

describe('verify', () => {
  test('Value should be refused if plaintext is not encapsulated or specified', async () => {
    const signedData = await SignedData.sign(
      plaintext,
      MEMBER_KEY_PAIR.privateKey,
      certificate,
      undefined,
      {
        encapsulatePlaintext: false,
      },
    );

    await expect(signedData.verify()).rejects.toMatchObject<Partial<CmsError>>({
      message: 'Plaintext should be encapsulated or explicitly set',
    });
  });

  test('Expected plaintext should be refused if one is already encapsulated', async () => {
    const signedData = await SignedData.sign(plaintext, MEMBER_KEY_PAIR.privateKey, certificate);

    await expect(signedData.verify(plaintext)).rejects.toThrowWithMessage(
      CmsError,
      'No specific plaintext should be expected because one is already encapsulated',
    );
  });

  test('Different detached plaintext should be rejected', async () => {
    const signedData = await SignedData.sign(
      plaintext,
      MEMBER_KEY_PAIR.privateKey,
      certificate,
      undefined,
      {
        encapsulatePlaintext: false,
      },
    );
    const differentPlaintext = arrayBufferFrom('this is an invalid plaintext');

    await expect(signedData.verify(differentPlaintext)).rejects.toBeInstanceOf(CmsError);
  });

  test('Different encapsulated plaintext should be rejected', async () => {
    // Let's tamper with the payload
    const signedData = await SignedData.sign(plaintext, MEMBER_KEY_PAIR.privateKey, certificate);
    const differentPlaintext = arrayBufferFrom('Different');
    signedData.pkijsSignedData.encapContentInfo = new EncapsulatedContentInfo({
      eContent: new OctetString({ valueHex: differentPlaintext }),
      eContentType: CMS_OIDS.DATA,
    });

    await expect(signedData.verify()).rejects.toBeInstanceOf(CmsError);
  });

  test('Invalid signature should be rejected', async () => {
    // Let's tamper with the signature
    const signedData = await SignedData.sign(plaintext, MEMBER_KEY_PAIR.privateKey, certificate);
    const differentSignature = arrayBufferFrom('Different');
    signedData.pkijsSignedData.signerInfos[0].signature = new OctetString({
      valueHex: differentSignature,
    });

    await expect(signedData.verify()).rejects.toThrowWithMessage(
      CmsError,
      'Invalid signature (PKI.js code: 14)',
    );
  });

  test('Valid signature without encapsulated plaintext should be accepted', async () => {
    const signedData = await SignedData.sign(
      plaintext,
      MEMBER_KEY_PAIR.privateKey,
      certificate,
      undefined,
      {
        encapsulatePlaintext: false,
      },
    );

    await expect(signedData.verify(plaintext)).toResolve();
  });

  test('Valid signature with encapsulated plaintext should be accepted', async () => {
    const signedData = await SignedData.sign(plaintext, MEMBER_KEY_PAIR.privateKey, certificate);
    await expect(signedData.verify()).toResolve();
  });
});

describe('plaintext', () => {
  test('Nothing should be output if plaintext is absent', () => {
    const pkijsSignedData = new PkijsSignedData();
    const signedData = new SignedData(pkijsSignedData);

    expect(signedData.plaintext).toBeNull();
  });

  test('Plaintext should be output if present', async () => {
    const signedData = await SignedData.sign(plaintext, MEMBER_KEY_PAIR.privateKey, certificate);

    expect(Buffer.from(signedData.plaintext!)).toStrictEqual(Buffer.from(plaintext));
  });

  test('Large plaintexts chunked by PKI.js should be put back together', async () => {
    const largePlaintext = arrayBufferFrom('a'.repeat(2 ** 20));
    const signedData = await SignedData.sign(
      largePlaintext,
      MEMBER_KEY_PAIR.privateKey,
      certificate,
    );

    expect(Buffer.from(signedData.plaintext!)).toStrictEqual(Buffer.from(largePlaintext));
  });
});

describe('signerCertificate', () => {
  test('Nothing should be output if there are no SignerInfo values', async () => {
    const signerCertificate = await generateStubCert({
      issuerPrivateKey: MEMBER_KEY_PAIR.privateKey,
      subjectPublicKey: MEMBER_KEY_PAIR.publicKey,
    });
    const signedData = await SignedData.sign(
      plaintext,
      MEMBER_KEY_PAIR.privateKey,
      signerCertificate,
    );
    signedData.pkijsSignedData.signerInfos.pop();

    expect(signedData.signerCertificate).toBeNull();
  });

  test('Certificate with same issuer but different SN should be ignored', async () => {
    const signerCertificate = await generateStubCert({
      issuerPrivateKey: MEMBER_KEY_PAIR.privateKey,
      subjectPublicKey: MEMBER_KEY_PAIR.publicKey,
    });
    const signedData = await SignedData.sign(
      plaintext,
      MEMBER_KEY_PAIR.privateKey,
      signerCertificate,
    );
    signedData.pkijsSignedData.signerInfos.forEach((signerInfo) => {
      // eslint-disable-next-line no-param-reassign
      (signerInfo.sid as IssuerAndSerialNumber).serialNumber = new Integer({
        value: -1,
      });
    });

    expect(signedData.signerCertificate).toBeNull();
  });

  test('Certificate with same SN but different issuer should be ignored', async () => {
    const signerCertificate = await generateStubCert({
      issuerPrivateKey: MEMBER_KEY_PAIR.privateKey,
      subjectPublicKey: MEMBER_KEY_PAIR.publicKey,
    });
    const signedData = await SignedData.sign(
      plaintext,
      MEMBER_KEY_PAIR.privateKey,
      signerCertificate,
    );
    signedData.pkijsSignedData.signerInfos.forEach((info) => {
      // eslint-disable-next-line no-param-reassign
      (info.sid as IssuerAndSerialNumber).issuer = new RelativeDistinguishedNames();
    });

    expect(signedData.signerCertificate).toBeNull();
  });

  test('Certificate with same SN and issuer should be output', async () => {
    const signedData = await SignedData.sign(plaintext, MEMBER_KEY_PAIR.privateKey, certificate);

    expect(signedData.signerCertificate?.isEqual(certificate)).toBeTrue();
  });
});

describe('certificates', () => {
  test('Attached CA certificates should be output', async () => {
    const rootCaKeyPair = await generateRsaKeyPair();
    const rootCaCertificate = await generateStubCert({
      attributes: { isCa: true },
      subjectPublicKey: rootCaKeyPair.publicKey,
    });
    const intermediateCaKeyPair = await generateRsaKeyPair();
    const intermediateCaCertificate = await generateStubCert({
      attributes: { isCa: true },
      issuerCertificate: rootCaCertificate,
      issuerPrivateKey: rootCaKeyPair.privateKey,
      subjectPublicKey: intermediateCaKeyPair.publicKey,
    });
    const signerKeyPair = await generateRsaKeyPair();
    const signerCertificate = await generateStubCert({
      issuerCertificate: intermediateCaCertificate,
      issuerPrivateKey: intermediateCaKeyPair.privateKey,
      subjectPublicKey: signerKeyPair.publicKey,
    });
    const signedData = await SignedData.sign(
      plaintext,
      signerKeyPair.privateKey,
      signerCertificate,
      [intermediateCaCertificate, rootCaCertificate],
    );

    const certificates = Array.from(signedData.certificates);
    expect(certificates.filter((cert) => cert.isEqual(rootCaCertificate))).toHaveLength(1);
    expect(certificates.filter((cert) => cert.isEqual(intermediateCaCertificate))).toHaveLength(1);
    expect(certificates.filter((cert) => cert.isEqual(signerCertificate))).toHaveLength(1);
  });
});
