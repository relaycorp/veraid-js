import * as asn1js from 'asn1js';
import { type Certificate as PkijsCertificate, IssuerAndSerialNumber, SignerInfo } from 'pkijs';

import {
  arrayBufferFrom,
  calculateDigestHex,
  expectAsn1ValuesToBeEqual,
  expectArrayBuffersToEqual,
  expectPkijsValuesToBeEqual,
  generateStubCert,
  sha256Hex,
} from '../../_test_utils.js';
import { CMS_OIDS } from '../../oids.js';
import { HashingAlgorithm } from '../algorithms.js';
import { generateRSAKeyPair } from '../keys.js';
import { RsaPssPrivateKey } from '../PrivateKey.js';
import { MockRsaPssProvider } from '../webcrypto/_test_utils.js';
import Certificate from '../x509/Certificate.js';
import { deserializeContentInfo, serializeContentInfo } from '../../../testUtils/asn1.js';
import CmsError from './CmsError.js';
import { SignedData } from './signedData.js';
import { expectFunctionToThrowError } from '../../../testUtils/errors.js';

const plaintext = arrayBufferFrom('Winter is coming');

let keyPair: CryptoKeyPair;
let certificate: Certificate;
beforeAll(async () => {
  keyPair = await generateRSAKeyPair();
  certificate = await generateStubCert({
    issuerPrivateKey: keyPair.privateKey,
    subjectPublicKey: keyPair.publicKey,
  });
});

afterEach(() => {
  jest.restoreAllMocks();
});

describe('sign', () => {
  test('SignedData version should be 1', async () => {
    const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate);

    expect(signedData.pkijsSignedData).toHaveProperty('version', 1);
  });

  test('Crypto in private key should be used if set', async () => {
    const provider = new MockRsaPssProvider();
    const privateKey = new RsaPssPrivateKey('SHA-256', provider);

    await expect(SignedData.sign(plaintext, privateKey, certificate)).toResolve();

    expect(provider.onSign).toBeCalled();
  });

  describe('SignerInfo', () => {
    test('There should only be one SignerInfo', async () => {
      const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate);

      expect(signedData.pkijsSignedData.signerInfos).toHaveLength(1);
      expect(signedData.pkijsSignedData.signerInfos[0]).toBeInstanceOf(SignerInfo);
    });

    test('Version should be 1', async () => {
      const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate);

      expect(signedData.pkijsSignedData.signerInfos[0]).toHaveProperty('version', 1);
    });

    test('SignerIdentifier should be IssuerAndSerialNumber', async () => {
      const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate);

      const signerInfo = signedData.pkijsSignedData.signerInfos[0];
      expect(signerInfo.sid).toBeInstanceOf(IssuerAndSerialNumber);
      expectPkijsValuesToBeEqual(signerInfo.sid.issuer, certificate.pkijsCertificate.issuer);
      expectAsn1ValuesToBeEqual(
        signerInfo.sid.serialNumber,
        certificate.pkijsCertificate.serialNumber,
      );
    });

    describe('SignedAttributes', () => {
      test('Signed attributes should be present', async () => {
        const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate);

        const signerInfo = signedData.pkijsSignedData.signerInfos[0];
        expect(signerInfo.signedAttrs).toBeInstanceOf(SignedAndUnsignedAttributes);
        expect(signerInfo.signedAttrs).toHaveProperty('type', 0);
      });

      test('Content type attribute should be set to CMS Data', async () => {
        const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate);

        const contentTypeAttribute = getSignerInfoAttribute(
          signedData.pkijsSignedData.signerInfos[0],
          CMS_OIDS.ATTR_CONTENT_TYPE,
        );
        // @ts-ignore
        expect(contentTypeAttribute.values).toHaveLength(1);
        expect(
          // @ts-ignore
          contentTypeAttribute.values[0].valueBlock.toString(),
        ).toEqual(CMS_OIDS.DATA);
      });

      test('Plaintext digest should be present', async () => {
        const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate);

        const digestAttribute = getSignerInfoAttribute(
          signedData.pkijsSignedData.signerInfos[0],
          CMS_OIDS.ATTR_DIGEST,
        );
        // @ts-ignore
        expect(digestAttribute.values).toHaveLength(1);
        expect(
          // @ts-ignore
          digestAttribute.values[0].valueBlock.valueHex,
        ).toBeTruthy();
      });
    });
  });

  describe('Attached certificates', () => {
    test('The signer certificate should be attached', async () => {
      const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate);

      expect(signedData.pkijsSignedData.certificates).toHaveLength(1);
      expectPkijsValuesToBeEqual(
        (signedData.pkijsSignedData.certificates as readonly PkijsCertificate[])[0],
        certificate.pkijsCertificate,
      );
    });

    test('CA certificate chain should optionally be attached', async () => {
      const rootCaCertificate = await generateStubCert();
      const intermediateCaCertificate = await generateStubCert();
      const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate, [
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

  describe('Hashing', () => {
    test('SHA-256 should be used by default', async () => {
      const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate);

      const digestAttribute = getSignerInfoAttribute(
        signedData.pkijsSignedData.signerInfos[0],
        CMS_OIDS.ATTR_DIGEST,
      );
      expect(
        // @ts-ignore
        Buffer.from(digestAttribute.values[0].valueBlock.valueHex).toString('hex'),
      ).toEqual(sha256Hex(plaintext));
    });

    test.each(['SHA-384', 'SHA-512'] as readonly HashingAlgorithm[])(
      '%s should be supported',
      async (hashingAlgorithmName) => {
        const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate, [], {
          hashingAlgorithmName,
        });

        const digestAttribute = getSignerInfoAttribute(
          signedData.pkijsSignedData.signerInfos[0],
          CMS_OIDS.ATTR_DIGEST,
        );
        const algorithmNameNodejs = hashingAlgorithmName.toLowerCase().replace('-', '');
        const digest = (digestAttribute as any).values[0].valueBlock.valueHex;
        expect(Buffer.from(digest).toString('hex')).toEqual(
          calculateDigestHex(algorithmNameNodejs, plaintext),
        );
      },
    );

    test('SHA-1 should not be a valid hashing function', async () => {
      expect.hasAssertions();

      try {
        await SignedData.sign(plaintext, keyPair.privateKey, certificate, [], {
          hashingAlgorithmName: 'SHA-1',
        } as any);
      } catch (error: any) {
        expect(error).toBeInstanceOf(CmsError);
        expect(error.message).toEqual('SHA-1 is disallowed by RS-018');
      }
    });
  });

  describe('Plaintext', () => {
    test('Plaintext should be encapsulated by default', async () => {
      const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate);

      const encapContentInfo = signedData.pkijsSignedData.encapContentInfo;
      expect(encapContentInfo).toBeInstanceOf(EncapsulatedContentInfo);
      expect(encapContentInfo).toHaveProperty('eContentType', CMS_OIDS.DATA);
      expect(encapContentInfo).toHaveProperty('eContent');
      const plaintextOctetString = encapContentInfo.eContent!.valueBlock
        .value[0] as asn1js.OctetString;
      expectArrayBuffersToEqual(
        plaintextOctetString.valueBlock.valueHexView.slice().buffer,
        plaintext,
      );
    });

    test('Content should not be encapsulated if requested', async () => {
      const signedData = await SignedData.sign(
        plaintext,
        keyPair.privateKey,
        certificate,
        undefined,
        { encapsulatePlaintext: false },
      );

      const encapContentInfo = signedData.pkijsSignedData.encapContentInfo;
      expect(encapContentInfo).toBeInstanceOf(EncapsulatedContentInfo);
      expect(encapContentInfo).toHaveProperty('eContentType', CMS_OIDS.DATA);
      expect(encapContentInfo).toHaveProperty('eContent', undefined);
    });
  });
});

describe('serialize', () => {
  test('SignedData value should be wrapped in ContentInfo', async () => {
    const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate);

    const signedDataSerialized = signedData.serialize();

    const contentInfo = deserializeContentInfo(signedDataSerialized);
    expect(contentInfo.content.toBER(false)).toEqual(
      signedData.pkijsSignedData.toSchema(true).toBER(false),
    );
  });

  test('ContentInfo OID should match that of SignedData values', async () => {
    const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate);

    const signedDataSerialized = signedData.serialize();

    const contentInfo = deserializeContentInfo(signedDataSerialized);
    expect(contentInfo.contentType).toEqual(CMS_OIDS.SIGNED_DATA);
  });
});

describe('deserialize', () => {
  test('A non-DER-encoded value should be refused', async () => {
    const invalidSignature = arrayBufferFrom('nope.jpeg');
    expect(() => SignedData.deserialize(invalidSignature)).toThrowWithMessage(
      CmsError,
      'Could not deserialize CMS ContentInfo: Value is not DER-encoded',
    );
  });

  test('ContentInfo wrapper should be required', async () => {
    const invalidSignature = new asn1js.Sequence().toBER(false);
    expect(() => SignedData.deserialize(invalidSignature)).toThrowWithMessage(
      CmsError,
      'Could not deserialize CMS ContentInfo: ' +
        "Object's schema was not verified against input data for ContentInfo",
    );
  });

  test('Malformed SignedData values should be refused', () => {
    const invalidSignature = serializeContentInfo(new asn1js.Sequence(), '1.2.3.4');
    expectFunctionToThrowError(
      () => SignedData.deserialize(invalidSignature),
      new CmsError('SignedData value is malformed', { cause: expect.anything() }),
    );
  });

  test('Well-formed SignedData values should be deserialized', async () => {
    const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate);
    const signedDataSerialized = signedData.serialize();

    const signedDataDeserialized = SignedData.deserialize(signedDataSerialized);

    expect(signedDataDeserialized.serialize()).toEqual(signedData.serialize());
  });
});

describe('verify', () => {
  test('Value should be refused if plaintext is not encapsulated or specified', async () => {
    const signedData = await SignedData.sign(
      plaintext,
      keyPair.privateKey,
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
    const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate);

    await expect(signedData.verify(plaintext)).rejects.toEqual(
      new CmsError('No specific plaintext should be expected because one is already encapsulated'),
    );
  });

  test('Invalid signature without encapsulated plaintext should be rejected', async () => {
    const signedData = await SignedData.sign(
      plaintext,
      keyPair.privateKey,
      certificate,
      undefined,
      {
        encapsulatePlaintext: false,
      },
    );
    const differentPlaintext = arrayBufferFrom('this is an invalid plaintext');

    await expect(signedData.verify(differentPlaintext)).rejects.toBeInstanceOf(CmsError);
  });

  test('Invalid signature with encapsulated plaintext should be rejected', async () => {
    // Let's tamper with the payload
    const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate);
    const differentPlaintext = arrayBufferFrom('Different');
    // tslint:disable-next-line:no-object-mutation
    signedData.pkijsSignedData.encapContentInfo = new EncapsulatedContentInfo({
      eContent: new asn1js.OctetString({ valueHex: differentPlaintext }),
      eContentType: CMS_OIDS.DATA,
    });

    await expect(signedData.verify()).rejects.toBeInstanceOf(CmsError);
  });

  test('Valid signature without encapsulated plaintext should be accepted', async () => {
    const signedData = await SignedData.sign(
      plaintext,
      keyPair.privateKey,
      certificate,
      undefined,
      {
        encapsulatePlaintext: false,
      },
    );

    await signedData.verify(plaintext);
  });

  test('Valid signature with encapsulated plaintext should be accepted', async () => {
    const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate);
    await signedData.verify();
  });
});

describe('plaintext', () => {
  test('Nothing should be output if plaintext is absent', async () => {
    const pkijsSignedData = new SignedData();
    const signedData = new SignedData(pkijsSignedData);

    await expect(signedData.plaintext).toBeNull();
  });

  test('Plaintext should be output if present', async () => {
    const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate);

    expectArrayBuffersToEqual(plaintext, signedData.plaintext!);
  });

  test('Large plaintexts chunked by PKI.js should be put back together', async () => {
    const largePlaintext = arrayBufferFrom('a'.repeat(2 ** 20));
    const signedData = await SignedData.sign(largePlaintext, keyPair.privateKey, certificate);

    expectArrayBuffersToEqual(largePlaintext, signedData.plaintext!);
  });
});

describe('signerCertificate', () => {
  test('Nothing should be output if there are no SignerInfo values', async () => {
    const signerCertificate = await generateStubCert({
      issuerPrivateKey: keyPair.privateKey,
      subjectPublicKey: keyPair.publicKey,
    });
    const signedData = await SignedData.sign(plaintext, keyPair.privateKey, signerCertificate);
    signedData.pkijsSignedData.signerInfos.pop();

    expect(signedData.signerCertificate).toBeNull();
  });

  test('Certificate with same issuer but different SN should be ignored', async () => {
    const signerCertificate = await generateStubCert({
      issuerPrivateKey: keyPair.privateKey,
      subjectPublicKey: keyPair.publicKey,
    });
    const signedData = await SignedData.sign(plaintext, keyPair.privateKey, signerCertificate);
    signedData.pkijsSignedData.signerInfos.forEach((signerInfo) => {
      (signerInfo.sid as IssuerAndSerialNumber).serialNumber = new asn1js.Integer({
        value: -1,
      });
    });

    expect(signedData.signerCertificate).toBeNull();
  });

  test('Certificate with same SN but different issuer should be ignored', async () => {
    const signerCertificate = await generateStubCert({
      issuerPrivateKey: keyPair.privateKey,
      subjectPublicKey: keyPair.publicKey,
    });
    const signedData = await SignedData.sign(plaintext, keyPair.privateKey, signerCertificate);
    signedData.pkijsSignedData.signerInfos.forEach((si) => {
      (si.sid as IssuerAndSerialNumber).issuer = new RelativeDistinguishedNames();
    });

    expect(signedData.signerCertificate).toBeNull();
  });

  test('Certificate with same SN and issuer should be output', async () => {
    const signedData = await SignedData.sign(plaintext, keyPair.privateKey, certificate);

    expect(signedData.signerCertificate?.isEqual(certificate)).toBeTrue();
  });
});

describe('certificates', () => {
  test('Attached CA certificates should be output', async () => {
    const rootCaKeyPair = await generateRSAKeyPair();
    const rootCaCertificate = await generateStubCert({
      attributes: { isCA: true },
      subjectPublicKey: rootCaKeyPair.publicKey,
    });
    const intermediateCaKeyPair = await generateRSAKeyPair();
    const intermediateCaCertificate = await generateStubCert({
      attributes: { isCA: true },
      issuerCertificate: rootCaCertificate,
      issuerPrivateKey: rootCaKeyPair.privateKey,
      subjectPublicKey: intermediateCaKeyPair.publicKey,
    });
    const signerKeyPair = await generateRSAKeyPair();
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
    expect(certificates.filter((c) => c.isEqual(rootCaCertificate))).toHaveLength(1);
    expect(certificates.filter((c) => c.isEqual(intermediateCaCertificate))).toHaveLength(1);
    expect(certificates.filter((c) => c.isEqual(signerCertificate))).toHaveLength(1);
  });
});

function getSignerInfoAttribute(signerInfo: SignerInfo, attributeOid: string): Attribute {
  const attributes = (signerInfo.signedAttrs as SignedAndUnsignedAttributes).attributes;
  const matchingAttrs = attributes.filter((a) => a.type === attributeOid);
  expect(matchingAttrs).toHaveLength(1);
  return matchingAttrs[0];
}
