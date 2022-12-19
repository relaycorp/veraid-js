import { addMinutes, setMilliseconds, subMinutes } from 'date-fns';

import { derSerializePublicKey, generateRsaKeyPair } from '../utils/keys.js';
import Certificate from '../utils/x509/Certificate.js';
import { getBasicConstraintsExtension } from '../../testUtils/pkijs.js';

import { selfIssueOrganisationCertificate } from './organisation.js';
import { issueMemberCertificate } from './member.js';

const ORG_NAME = 'example.com';
const MEMBER_NAME = 'alice';
const NOW = setMilliseconds(new Date(), 0);
const START_DATE = subMinutes(NOW, 5);
const EXPIRY_DATE = addMinutes(NOW, 5);

let orgPrivateKey: CryptoKey;
let orgCertificate: ArrayBuffer;
beforeAll(async () => {
  const orgKeyPair = await generateRsaKeyPair();
  orgPrivateKey = orgKeyPair.privateKey;
  orgCertificate = await selfIssueOrganisationCertificate(ORG_NAME, orgKeyPair, EXPIRY_DATE, {
    startDate: START_DATE,
  });
});

let memberPublicKey: CryptoKey;
beforeAll(async () => {
  const memberKeyPair = await generateRsaKeyPair();
  memberPublicKey = memberKeyPair.publicKey;
});

describe('issueMemberCertificate', () => {
  describe('Common Name', () => {
    test('should be the at sign if member is a bot', async () => {
      const serialisation = await issueMemberCertificate(
        undefined,
        memberPublicKey,
        orgCertificate,
        orgPrivateKey,
        EXPIRY_DATE,
      );

      const certificate = Certificate.deserialize(serialisation);
      expect(certificate.commonName).toBe('@');
    });

    test('should be the specified name if set', async () => {
      const serialisation = await issueMemberCertificate(
        MEMBER_NAME,
        memberPublicKey,
        orgCertificate,
        orgPrivateKey,
        EXPIRY_DATE,
      );

      const certificate = Certificate.deserialize(serialisation);
      expect(certificate.commonName).toBe(MEMBER_NAME);
    });
  });

  test('Member public key should be honoured', async () => {
    const serialisation = await issueMemberCertificate(
      MEMBER_NAME,
      memberPublicKey,
      orgCertificate,
      orgPrivateKey,
      EXPIRY_DATE,
    );

    const certificate = Certificate.deserialize(serialisation);
    await expect(derSerializePublicKey(await certificate.getPublicKey())).resolves.toStrictEqual(
      await derSerializePublicKey(memberPublicKey),
    );
  });

  test('Certificate should be issued by organisation', async () => {
    const serialisation = await issueMemberCertificate(
      MEMBER_NAME,
      memberPublicKey,
      orgCertificate,
      orgPrivateKey,
      EXPIRY_DATE,
    );

    const memberCertificate = Certificate.deserialize(serialisation);
    const orgCertificateDeserialised = Certificate.deserialize(orgCertificate);
    await expect(
      memberCertificate.getCertificationPath([], [orgCertificateDeserialised]),
    ).resolves.toHaveLength(2);
  });

  test('Expiry date should match specified one', async () => {
    const serialisation = await issueMemberCertificate(
      MEMBER_NAME,
      memberPublicKey,
      orgCertificate,
      orgPrivateKey,
      EXPIRY_DATE,
    );

    const certificate = Certificate.deserialize(serialisation);
    expect(certificate.expiryDate).toStrictEqual(EXPIRY_DATE);
  });

  describe('Start date', () => {
    test('should default to now', async () => {
      const preIssuanceDate = new Date();

      const serialisation = await issueMemberCertificate(
        MEMBER_NAME,
        memberPublicKey,
        orgCertificate,
        orgPrivateKey,
        EXPIRY_DATE,
      );

      const certificate = Certificate.deserialize(serialisation);
      expect(certificate.startDate).toBeBetween(setMilliseconds(preIssuanceDate, 0), new Date());
    });

    test('should match explicit date if set', async () => {
      const serialisation = await issueMemberCertificate(
        MEMBER_NAME,
        memberPublicKey,
        orgCertificate,
        orgPrivateKey,
        EXPIRY_DATE,
        { startDate: START_DATE },
      );

      const certificate = Certificate.deserialize(serialisation);
      expect(certificate.startDate).toStrictEqual(START_DATE);
    });
  });

  describe('Basic constraints extension', () => {
    test('Subject should not be a CA', async () => {
      const serialisation = await issueMemberCertificate(
        MEMBER_NAME,
        memberPublicKey,
        orgCertificate,
        orgPrivateKey,
        EXPIRY_DATE,
      );

      const certificate = Certificate.deserialize(serialisation);
      const basicConstraints = getBasicConstraintsExtension(certificate.pkijsCertificate);
      expect(basicConstraints.cA).toBeFalse();
    });

    test('Path length should be zero', async () => {
      const serialisation = await issueMemberCertificate(
        MEMBER_NAME,
        memberPublicKey,
        orgCertificate,
        orgPrivateKey,
        EXPIRY_DATE,
      );

      const certificate = Certificate.deserialize(serialisation);
      const basicConstraints = getBasicConstraintsExtension(certificate.pkijsCertificate);
      expect(basicConstraints.pathLenConstraint).toBe(0);
    });
  });
});
