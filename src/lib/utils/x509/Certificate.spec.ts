import { jest } from '@jest/globals';
import { OctetString } from 'asn1js';
import { addDays, addSeconds, setMilliseconds } from 'date-fns';
import { advanceTo, clear as dateMockClear } from 'jest-date-mock';
import {
  AuthorityKeyIdentifier,
  Certificate as PkijsCertificate,
  CryptoEngine,
  PublicKeyInfo,
} from 'pkijs';

import { AUTHORITY_KEY, BASIC_CONSTRAINTS, COMMON_NAME, SUBJECT_KEY } from '../../oids.js';
import { derSerializePublicKey } from '../keys/serialisation.js';
import { getEngineForPrivateKey } from '../webcrypto/engine.js';
import { MockRsaPssProvider } from '../../../testUtils/webcrypto/MockRsaPssProvider.js';
import { getBasicConstraintsExtension, getExtension } from '../../../testUtils/pkijs.js';
import { calculateDigest } from '../../../testUtils/crypto.js';
import { generateStubCert } from '../../../testUtils/pki.js';
import { derDeserialize } from '../asn1.js';
import { RsaPssPrivateKey } from '../keys/RsaPssPrivateKey.js';
import { arrayBufferFrom } from '../../../testUtils/buffers.js';
import { generateRsaKeyPair } from '../keys/generation.js';
import { NODE_ENGINE } from '../pkijs.js';

import Certificate from './Certificate.js';
import CertificateError from './CertificateError.js';

const baseCertificateOptions = {
  commonName: 'the CN',
  validityEndDate: addDays(new Date(), 1),
};

let issuerKeyPair: CryptoKeyPair;
let issuerCertificate: Certificate;
let subjectKeyPair: CryptoKeyPair;
beforeAll(async () => {
  issuerKeyPair = await generateRsaKeyPair();
  issuerCertificate = await Certificate.issue({
    ...baseCertificateOptions,
    isCa: true,
    issuerPrivateKey: issuerKeyPair.privateKey,
    subjectPublicKey: issuerKeyPair.publicKey,
  });

  subjectKeyPair = await generateRsaKeyPair();
});

afterEach(() => {
  jest.restoreAllMocks();
  dateMockClear();
});

async function getPublicKeyDigest(publicKey: CryptoKey): Promise<string> {
  const publicKeyDer = await derSerializePublicKey(publicKey);
  return calculateDigest('sha256', publicKeyDer).toString('hex');
}

describe('constructor', () => {
  describe('validityPeriod', () => {
    test('Start date after expiry date should be refused', async () => {
      const { pkijsCertificate } = await generateStubCert();
      pkijsCertificate.notBefore.value = addSeconds(pkijsCertificate.notAfter.value, 1);

      expect(() => new Certificate(pkijsCertificate)).toThrowWithMessage(
        Error,
        /^End date should not be before start date/u,
      );
    });

    test('Start date equal to expiry date should be allowed', async () => {
      const { pkijsCertificate } = await generateStubCert();
      pkijsCertificate.notBefore.value = pkijsCertificate.notAfter.value;

      const certificate = new Certificate(pkijsCertificate);

      expect(certificate.validityPeriod.start).toStrictEqual(pkijsCertificate.notBefore.value);
      expect(certificate.validityPeriod.end).toStrictEqual(pkijsCertificate.notBefore.value);
    });

    test('Start date before expiry date should be allowed', async () => {
      const { pkijsCertificate } = await generateStubCert();
      expect(pkijsCertificate.notBefore.value).toBeBefore(pkijsCertificate.notAfter.value);

      const certificate = new Certificate(pkijsCertificate);
      expect(certificate.validityPeriod.start).toStrictEqual(pkijsCertificate.notBefore.value);
      expect(certificate.validityPeriod.end).toStrictEqual(pkijsCertificate.notAfter.value);
    });
  });
});

describe('deserialize()', () => {
  test('should deserialize valid DER-encoded certificates', async () => {
    // Serialize manually just in this test to avoid depending on .serialize()
    const { pkijsCertificate } = await generateStubCert();
    const certDer = pkijsCertificate.toSchema(true).toBER(false);

    const cert = Certificate.deserialize(certDer);

    expect(cert.pkijsCertificate.subject.typesAndValues[0].type).toBe(
      pkijsCertificate.subject.typesAndValues[0].type,
    );
    expect(cert.pkijsCertificate.subject.typesAndValues[0].value.valueBlock.value).toBe(
      pkijsCertificate.subject.typesAndValues[0].value.valueBlock.value,
    );
  });

  test('should error out with invalid DER values', () => {
    const invalidDer = arrayBufferFrom('nope');
    expect(() => Certificate.deserialize(invalidDer)).toThrowWithMessage(
      Error,
      'Value is not DER-encoded',
    );
  });
});

describe('issue()', () => {
  test('should create an X.509 v3 certificate', async () => {
    const cert = await Certificate.issue({
      ...baseCertificateOptions,
      issuerPrivateKey: subjectKeyPair.privateKey,
      subjectPublicKey: subjectKeyPair.publicKey,
    });

    // v3 is serialized as integer 2
    expect(cert.pkijsCertificate.version).toBe(2);
  });

  test('should import the public key into the certificate', async () => {
    const importKeySpy = jest.spyOn(PublicKeyInfo.prototype, 'importKey');
    await Certificate.issue({
      ...baseCertificateOptions,
      issuerPrivateKey: subjectKeyPair.privateKey,
      subjectPublicKey: subjectKeyPair.publicKey,
    });

    expect(importKeySpy).toHaveBeenCalledTimes(1);
    expect(importKeySpy).toHaveBeenCalledWith(subjectKeyPair.publicKey, NODE_ENGINE);
  });

  test('should be signed with the specified private key', async () => {
    const signSpy = jest.spyOn(PkijsCertificate.prototype, 'sign');
    await Certificate.issue({
      ...baseCertificateOptions,
      issuerPrivateKey: subjectKeyPair.privateKey,
      subjectPublicKey: subjectKeyPair.publicKey,
    });

    expect(signSpy).toHaveBeenCalledTimes(1);
    expect(signSpy).toHaveBeenCalledWith(
      subjectKeyPair.privateKey,
      ((subjectKeyPair.privateKey.algorithm as RsaHashedKeyGenParams).hash as Algorithm).name,
      NODE_ENGINE,
    );
  });

  test('should use crypto engine in private key if set', async () => {
    const privateKey = new RsaPssPrivateKey('SHA-256', new MockRsaPssProvider());
    const signSpy = jest.spyOn(PkijsCertificate.prototype, 'sign');

    await expect(
      Certificate.issue({
        ...baseCertificateOptions,
        issuerPrivateKey: privateKey,
        subjectPublicKey: subjectKeyPair.publicKey,
      }),
    ).toResolve();

    const engine = getEngineForPrivateKey(privateKey);
    expect(engine).toBeInstanceOf(CryptoEngine);
    expect(signSpy).toHaveBeenCalledWith(expect.anything(), expect.anything(), engine);
  });

  test('should generate a positive serial number', async () => {
    const certificates = await Promise.all(
      Array.from({ length: 10 }, async () =>
        Certificate.issue({
          ...baseCertificateOptions,
          issuerPrivateKey: subjectKeyPair.privateKey,
          subjectPublicKey: subjectKeyPair.publicKey,
        }),
      ),
    );
    for (const cert of certificates) {
      const serialNumberSerialized = cert.pkijsCertificate.serialNumber.valueBlock.valueHexView;
      expect(serialNumberSerialized).toHaveLength(8);
      expect(serialNumberSerialized[0]).toBeGreaterThanOrEqual(0);
      expect(serialNumberSerialized[0]).toBeLessThanOrEqual(127);
    }
  });

  test('should create a certificate valid from now by default', async () => {
    // We need to check it's rounded down to the nearest second
    const now = setMilliseconds(new Date(), 1);
    advanceTo(now);

    const cert = await Certificate.issue({
      ...baseCertificateOptions,
      issuerPrivateKey: subjectKeyPair.privateKey,
      subjectPublicKey: subjectKeyPair.publicKey,
    });

    expect(cert.validityPeriod.start).toStrictEqual(setMilliseconds(now, 0));
  });

  test('should honor a custom start validity date', async () => {
    const startDate = new Date(2019, 1, 1, 1, 1, 1, 1);

    const cert = await Certificate.issue({
      ...baseCertificateOptions,
      issuerPrivateKey: subjectKeyPair.privateKey,
      subjectPublicKey: subjectKeyPair.publicKey,
      validityStartDate: startDate,
    });

    expect(cert.validityPeriod.start).toStrictEqual(setMilliseconds(startDate, 0));
  });

  describe('Validity end date', () => {
    test('should honor explicit one', async () => {
      const endDate = setMilliseconds(addDays(new Date(), 1), 0);

      const cert = await Certificate.issue({
        ...baseCertificateOptions,
        issuerPrivateKey: subjectKeyPair.privateKey,
        subjectPublicKey: subjectKeyPair.publicKey,
        validityEndDate: endDate,
      });

      expect(cert.validityPeriod.end).toStrictEqual(endDate);
    });

    test('should be capped at that of issuer', async () => {
      const endDate = addSeconds(issuerCertificate.validityPeriod.end, 1);

      const cert = await Certificate.issue({
        ...baseCertificateOptions,
        issuerCertificate,
        issuerPrivateKey: subjectKeyPair.privateKey,
        subjectPublicKey: subjectKeyPair.publicKey,
        validityEndDate: endDate,
      });

      expect(cert.validityPeriod.end).toStrictEqual(issuerCertificate.validityPeriod.end);
    });

    test('should be rounded down to nearest second', async () => {
      const endDate = addDays(issuerCertificate.validityPeriod.end, 1);

      const cert = await Certificate.issue({
        ...baseCertificateOptions,
        issuerPrivateKey: subjectKeyPair.privateKey,
        subjectPublicKey: subjectKeyPair.publicKey,
        validityEndDate: endDate,
      });

      expect(cert.validityPeriod.end).toStrictEqual(setMilliseconds(endDate, 0));
    });
  });

  test('should store the specified Common Name (CN) in the subject', async () => {
    const commonName = 'this is the CN';
    const cert = await Certificate.issue({
      ...baseCertificateOptions,
      commonName,
      issuerPrivateKey: subjectKeyPair.privateKey,
      subjectPublicKey: subjectKeyPair.publicKey,
    });

    const subjectDnAttributes = cert.pkijsCertificate.subject.typesAndValues;
    expect(subjectDnAttributes).toHaveLength(1);
    expect(subjectDnAttributes[0].type).toBe(COMMON_NAME);
    expect(subjectDnAttributes[0].value.valueBlock.value).toStrictEqual(commonName);
  });

  test('should set issuer DN to that of subject when self-issuing certificates', async () => {
    const cert = await Certificate.issue({
      ...baseCertificateOptions,
      issuerPrivateKey: subjectKeyPair.privateKey,
      subjectPublicKey: subjectKeyPair.publicKey,
    });

    const subjectDn = cert.pkijsCertificate.subject.typesAndValues;
    const issuerDn = cert.pkijsCertificate.issuer.typesAndValues;
    expect(issuerDn).toHaveLength(1);
    expect(issuerDn[0].type).toBe(COMMON_NAME);
    expect(issuerDn[0].value.valueBlock.value).toBe(subjectDn[0].value.valueBlock.value);
  });

  test('should accept an issuer marked as CA', async () => {
    const issuerCert = await Certificate.issue({
      ...baseCertificateOptions,
      isCa: true,
      issuerPrivateKey: issuerKeyPair.privateKey,
      subjectPublicKey: issuerKeyPair.publicKey,
    });

    await expect(
      Certificate.issue({
        ...baseCertificateOptions,
        issuerCertificate: issuerCert,
        issuerPrivateKey: issuerKeyPair.privateKey,
        subjectPublicKey: subjectKeyPair.publicKey,
      }),
    ).toResolve();
  });

  test('should refuse an issuer certificate without extensions', async () => {
    const invalidIssuerCertificate = await Certificate.issue({
      ...baseCertificateOptions,
      isCa: false,
      issuerPrivateKey: issuerKeyPair.privateKey,
      subjectPublicKey: issuerKeyPair.publicKey,
    });

    invalidIssuerCertificate.pkijsCertificate.extensions = undefined;

    await expect(
      Certificate.issue({
        ...baseCertificateOptions,
        issuerCertificate: invalidIssuerCertificate,
        issuerPrivateKey: issuerKeyPair.privateKey,
        subjectPublicKey: subjectKeyPair.publicKey,
      }),
    ).rejects.toStrictEqual(
      new CertificateError('Basic constraints extension is missing from issuer certificate'),
    );
  });

  test('should refuse an issuer certificate with an empty set of extensions', async () => {
    const invalidIssuerCertificate = await Certificate.issue({
      ...baseCertificateOptions,
      isCa: false,
      issuerPrivateKey: issuerKeyPair.privateKey,
      subjectPublicKey: issuerKeyPair.publicKey,
    });

    invalidIssuerCertificate.pkijsCertificate.extensions = [];

    await expect(
      Certificate.issue({
        ...baseCertificateOptions,
        issuerCertificate: invalidIssuerCertificate,
        issuerPrivateKey: subjectKeyPair.privateKey,
        subjectPublicKey: subjectKeyPair.publicKey,
      }),
    ).rejects.toStrictEqual(
      new CertificateError('Basic constraints extension is missing from issuer certificate'),
    );
  });

  test('should refuse an issuer certificate without basic constraints extension', async () => {
    const invalidIssuerCertificate = await Certificate.issue({
      ...baseCertificateOptions,
      isCa: false,
      issuerPrivateKey: subjectKeyPair.privateKey,
      subjectPublicKey: issuerKeyPair.publicKey,
    });

    invalidIssuerCertificate.pkijsCertificate.extensions =
      invalidIssuerCertificate.pkijsCertificate.extensions!.filter(
        (extension) => extension.extnID !== BASIC_CONSTRAINTS,
      );

    await expect(
      Certificate.issue({
        ...baseCertificateOptions,
        issuerCertificate: invalidIssuerCertificate,
        issuerPrivateKey: subjectKeyPair.privateKey,
        subjectPublicKey: subjectKeyPair.publicKey,
      }),
    ).rejects.toStrictEqual(
      new CertificateError('Basic constraints extension is missing from issuer certificate'),
    );
  });

  test('should refuse an issuer not marked as CA', async () => {
    const invalidIssuerCertificate = await Certificate.issue({
      ...baseCertificateOptions,
      isCa: false,
      issuerPrivateKey: issuerKeyPair.privateKey,
      subjectPublicKey: issuerKeyPair.publicKey,
    });

    await expect(
      Certificate.issue({
        ...baseCertificateOptions,
        issuerCertificate: invalidIssuerCertificate,
        issuerPrivateKey: subjectKeyPair.privateKey,
        subjectPublicKey: subjectKeyPair.publicKey,
      }),
    ).rejects.toStrictEqual(new CertificateError('Issuer is not a CA'));
  });

  test('should set issuer DN to that of CA', async () => {
    const subjectCert = await Certificate.issue({
      ...baseCertificateOptions,
      issuerCertificate,
      issuerPrivateKey: issuerKeyPair.privateKey,
      subjectPublicKey: subjectKeyPair.publicKey,
    });

    const subjectCertIssuerDn = subjectCert.pkijsCertificate.issuer.typesAndValues;
    expect(subjectCertIssuerDn).toHaveLength(1);
    expect(subjectCertIssuerDn[0].type).toBe(COMMON_NAME);
    const issuerCn =
      issuerCertificate.pkijsCertificate.subject.typesAndValues[0].value.valueBlock.value;
    expect(subjectCertIssuerDn[0].value.valueBlock.value).toBe(issuerCn);
  });

  describe('Basic Constraints extension', () => {
    test('Extension should be included and marked as critical', async () => {
      const cert = await Certificate.issue({
        ...baseCertificateOptions,
        issuerPrivateKey: subjectKeyPair.privateKey,
        subjectPublicKey: subjectKeyPair.publicKey,
      });

      const bcExtension = getExtension(cert.pkijsCertificate, BASIC_CONSTRAINTS);
      expect(bcExtension?.critical).toBeTrue();
    });

    test('CA flag should be false by default', async () => {
      const cert = await Certificate.issue({
        ...baseCertificateOptions,
        issuerPrivateKey: subjectKeyPair.privateKey,
        subjectPublicKey: subjectKeyPair.publicKey,
      });

      const basicConstraints = getBasicConstraintsExtension(cert.pkijsCertificate);
      expect(basicConstraints).toHaveProperty('cA', false);
    });

    test('CA flag should be enabled if requested', async () => {
      const cert = await Certificate.issue({
        ...baseCertificateOptions,
        isCa: true,
        issuerPrivateKey: subjectKeyPair.privateKey,
        subjectPublicKey: subjectKeyPair.publicKey,
      });
      const basicConstraints = getBasicConstraintsExtension(cert.pkijsCertificate);
      expect(basicConstraints).toHaveProperty('cA', true);
    });

    test('pathLenConstraint should be 0 by default', async () => {
      const cert = await Certificate.issue({
        ...baseCertificateOptions,
        issuerPrivateKey: subjectKeyPair.privateKey,
        subjectPublicKey: subjectKeyPair.publicKey,
      });

      const basicConstraints = getBasicConstraintsExtension(cert.pkijsCertificate);
      expect(basicConstraints).toHaveProperty('pathLenConstraint', 0);
    });

    test('pathLenConstraint can be set to a custom value <= 2', async () => {
      const pathLengthConstraint = 2;
      const cert = await Certificate.issue({
        ...baseCertificateOptions,
        issuerPrivateKey: subjectKeyPair.privateKey,
        pathLenConstraint: pathLengthConstraint,
        subjectPublicKey: subjectKeyPair.publicKey,
      });

      const basicConstraints = getBasicConstraintsExtension(cert.pkijsCertificate);
      expect(basicConstraints).toHaveProperty('pathLenConstraint', pathLengthConstraint);
    });

    test('pathLenConstraint should not be negative', async () => {
      await expect(
        Certificate.issue({
          ...baseCertificateOptions,
          issuerPrivateKey: subjectKeyPair.privateKey,
          pathLenConstraint: -1,
          subjectPublicKey: subjectKeyPair.publicKey,
        }),
      ).rejects.toStrictEqual(new CertificateError('pathLenConstraint must be >= 0 (got -1)'));
    });
  });

  describe('Authority Key Identifier extension', () => {
    function getAkiExtension(subjectCert: Certificate): AuthorityKeyIdentifier {
      const akiExtension = getExtension(subjectCert.pkijsCertificate, AUTHORITY_KEY);
      const akiExtensionAsn1 = derDeserialize(akiExtension!.extnValue.valueBlock.valueHexView);
      return new AuthorityKeyIdentifier({ schema: akiExtensionAsn1 });
    }

    test('should not be critical', async () => {
      const cert = await Certificate.issue({
        ...baseCertificateOptions,
        issuerPrivateKey: subjectKeyPair.privateKey,
        subjectPublicKey: subjectKeyPair.publicKey,
      });

      const akiExtension = getExtension(cert.pkijsCertificate, AUTHORITY_KEY);
      expect(akiExtension!.critical).toBe(false);
    });

    test('should correspond to subject when self-issued', async () => {
      const cert = await Certificate.issue({
        ...baseCertificateOptions,
        issuerPrivateKey: subjectKeyPair.privateKey,
        subjectPublicKey: subjectKeyPair.publicKey,
      });

      const akiExtension = getAkiExtension(cert);
      expect(akiExtension.keyIdentifier).toBeInstanceOf(OctetString);
      const keyIdBuffer = Buffer.from(akiExtension.keyIdentifier!.valueBlock.valueHexView);
      expect(keyIdBuffer.toString('hex')).toStrictEqual(
        await getPublicKeyDigest(subjectKeyPair.publicKey),
      );
    });

    test('should correspond to issuer key when different from subject', async () => {
      const subjectCert = await Certificate.issue({
        ...baseCertificateOptions,
        issuerCertificate,
        issuerPrivateKey: subjectKeyPair.privateKey,
        subjectPublicKey: subjectKeyPair.publicKey,
      });

      const akiExtension = getAkiExtension(subjectCert);
      expect(akiExtension.keyIdentifier).toBeInstanceOf(OctetString);
      const keyIdBuffer = Buffer.from(akiExtension.keyIdentifier!.valueBlock.valueHexView);
      expect(keyIdBuffer.toString('hex')).toStrictEqual(
        await getPublicKeyDigest(issuerKeyPair.publicKey),
      );
    });
  });

  test('Subject Key Identifier extension should correspond to subject key', async () => {
    const subjectCert = await Certificate.issue({
      ...baseCertificateOptions,
      issuerCertificate,
      issuerPrivateKey: subjectKeyPair.privateKey,
      subjectPublicKey: subjectKeyPair.publicKey,
    });

    const skiExtension = getExtension(subjectCert.pkijsCertificate, SUBJECT_KEY);
    expect(skiExtension!.critical).toBe(false);
    const skiExtensionAsn1 = derDeserialize(skiExtension!.extnValue.valueBlock.valueHexView);
    expect(skiExtensionAsn1).toBeInstanceOf(OctetString);

    const keyIdBuffer = Buffer.from((skiExtensionAsn1 as OctetString).valueBlock.valueHexView);
    expect(keyIdBuffer.toString('hex')).toStrictEqual(
      await getPublicKeyDigest(subjectKeyPair.publicKey),
    );
  });
});

test('serialize() should return a DER-encoded buffer', async () => {
  const cert = await generateStubCert();

  const certDer = cert.serialize();

  const asn1Value = derDeserialize(certDer);
  const pkijsCert = new PkijsCertificate({ schema: asn1Value });

  const subjectDnAttributes = pkijsCert.subject.typesAndValues;
  expect(subjectDnAttributes).toHaveLength(1);
  expect(subjectDnAttributes[0].type).toBe(COMMON_NAME);
  expect(subjectDnAttributes[0].value.valueBlock.value).toBe(cert.commonName);

  const issuerDnAttributes = pkijsCert.issuer.typesAndValues;
  expect(issuerDnAttributes).toHaveLength(1);
  expect(issuerDnAttributes[0].type).toBe(COMMON_NAME);
  expect(issuerDnAttributes[0].value.valueBlock.value).toBe(cert.commonName);
});

test('getSerialNumber() should return the serial number as a buffer', async () => {
  const cert = await generateStubCert();

  expect(cert.serialNumber).toStrictEqual(
    Buffer.from(cert.pkijsCertificate.serialNumber.valueBlock.valueHexView),
  );
});

describe('commonName', () => {
  test('should return the address when found', async () => {
    const cert = await generateStubCert();

    const subjectDn = cert.pkijsCertificate.subject.typesAndValues;

    expect(cert.commonName).toStrictEqual(subjectDn[0].value.valueBlock.value);
  });

  test('should error out when the address is not found', async () => {
    const cert = await generateStubCert();

    cert.pkijsCertificate.subject.typesAndValues = [];

    expect(() => cert.commonName).toThrowWithMessage(
      CertificateError,
      'Distinguished Name does not contain Common Name',
    );
  });
});

describe('isEqual', () => {
  test('Equal certificates should be reported as such', async () => {
    const cert1 = await generateStubCert();
    const cert2 = Certificate.deserialize(cert1.serialize());

    expect(cert1.isEqual(cert2)).toBeTrue();
  });

  test('Different certificates should be reported as such', async () => {
    const cert1 = await generateStubCert();
    const cert2 = await generateStubCert();

    expect(cert1.isEqual(cert2)).toBeFalse();
  });
});

describe('getCertificationPath', () => {
  let stubTrustedCaPrivateKey: CryptoKey;
  let stubRootCa: Certificate;
  beforeAll(async () => {
    const trustedCaKeyPair = await generateRsaKeyPair();
    stubTrustedCaPrivateKey = trustedCaKeyPair.privateKey;
    stubRootCa = await generateStubCert({
      attributes: { isCa: true },
      issuerPrivateKey: trustedCaKeyPair.privateKey,
      subjectPublicKey: trustedCaKeyPair.publicKey,
    });
  });

  test('Cert issued by trusted cert should be trusted', async () => {
    const cert = await generateStubCert({
      issuerCertificate: stubRootCa,
      issuerPrivateKey: stubTrustedCaPrivateKey,
    });

    await expect(cert.getCertificationPath([], [stubRootCa])).resolves.toStrictEqual([
      cert,
      stubRootCa,
    ]);
  });

  test('Cert not issued by trusted cert should not be trusted', async () => {
    const cert = await generateStubCert();

    await expect(cert.getCertificationPath([], [stubRootCa])).rejects.toStrictEqual(
      new CertificateError('No valid certificate paths found'),
    );
  });

  test('Expired certificate should not be trusted', async () => {
    const validityEndDate = new Date();
    validityEndDate.setMinutes(validityEndDate.getMinutes() - 1);
    const validityStartDate = new Date(validityEndDate);
    validityStartDate.setMinutes(validityStartDate.getMinutes() - 1);
    const cert = await generateStubCert({ attributes: { validityEndDate, validityStartDate } });

    await expect(cert.getCertificationPath([], [stubRootCa])).rejects.toStrictEqual(
      new CertificateError('No valid certificate paths found'),
    );
  });

  test('Cert issued by untrusted intermediate should be trusted if root is trusted', async () => {
    const intermediateCaKeyPair = await generateRsaKeyPair();
    const intermediateCaCert = await generateStubCert({
      attributes: { isCa: true },
      issuerCertificate: stubRootCa,
      issuerPrivateKey: stubTrustedCaPrivateKey,
      subjectPublicKey: intermediateCaKeyPair.publicKey,
    });

    const cert = await generateStubCert({
      issuerCertificate: intermediateCaCert,
      issuerPrivateKey: intermediateCaKeyPair.privateKey,
    });

    await expect(
      cert.getCertificationPath([intermediateCaCert], [stubRootCa]),
    ).resolves.toStrictEqual([cert, intermediateCaCert, stubRootCa]);
  });

  test('Cert issued by trusted intermediate CA should be trusted', async () => {
    const intermediateCaKeyPair = await generateRsaKeyPair();
    const intermediateCaCert = await generateStubCert({
      attributes: { isCa: true },
      issuerCertificate: stubRootCa,
      issuerPrivateKey: stubTrustedCaPrivateKey,
      subjectPublicKey: intermediateCaKeyPair.publicKey,
    });

    const cert = await generateStubCert({
      issuerCertificate: intermediateCaCert,
      issuerPrivateKey: intermediateCaKeyPair.privateKey,
    });

    await expect(cert.getCertificationPath([], [intermediateCaCert])).resolves.toStrictEqual([
      cert,
      intermediateCaCert,
    ]);
  });

  test('Cert issued by untrusted intermediate CA should not be trusted', async () => {
    const untrustedIntermediateCaKeyPair = await generateRsaKeyPair();
    const untrustedIntermediateCaCert = await generateStubCert({
      attributes: { isCa: true },
      issuerPrivateKey: untrustedIntermediateCaKeyPair.privateKey,
      subjectPublicKey: untrustedIntermediateCaKeyPair.publicKey,
    });

    const cert = await generateStubCert({
      issuerCertificate: untrustedIntermediateCaCert,
      issuerPrivateKey: untrustedIntermediateCaKeyPair.privateKey,
    });

    await expect(
      cert.getCertificationPath([untrustedIntermediateCaCert], [stubRootCa]),
    ).rejects.toStrictEqual(new CertificateError('No valid certificate paths found'));
  });

  test('Including trusted intermediate CA should not make certificate trusted', async () => {
    const intermediateCaKeyPair = await generateRsaKeyPair();
    const trustedIntermediateCaCert = await generateStubCert({
      attributes: { isCa: true },
      issuerPrivateKey: intermediateCaKeyPair.privateKey,
      subjectPublicKey: intermediateCaKeyPair.publicKey,
    });

    const cert = await generateStubCert();

    await expect(
      cert.getCertificationPath([trustedIntermediateCaCert], [stubRootCa]),
    ).rejects.toStrictEqual(new CertificateError('No valid certificate paths found'));
  });

  test('Root certificate should be ignored if passed as intermediate unnecessarily', async () => {
    const intermediateCaKeyPair = await generateRsaKeyPair();
    const intermediateCaCert = await generateStubCert({
      attributes: { isCa: true },
      issuerCertificate: stubRootCa,
      issuerPrivateKey: stubTrustedCaPrivateKey,
      subjectPublicKey: intermediateCaKeyPair.publicKey,
    });

    const cert = await generateStubCert({
      issuerCertificate: intermediateCaCert,
      issuerPrivateKey: intermediateCaKeyPair.privateKey,
    });

    await expect(
      cert.getCertificationPath([intermediateCaCert, stubRootCa], [intermediateCaCert]),
    ).resolves.toStrictEqual([cert, intermediateCaCert]);
  });
});

test('getPublicKey should return the subject public key', async () => {
  const cert = await generateStubCert({
    issuerPrivateKey: subjectKeyPair.privateKey,
    subjectPublicKey: subjectKeyPair.publicKey,
  });

  const publicKey = await cert.getPublicKey();

  await expect(derSerializePublicKey(publicKey)).resolves.toStrictEqual(
    await derSerializePublicKey(subjectKeyPair.publicKey),
  );
});
