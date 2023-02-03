import { addMinutes, setMilliseconds, subMinutes } from 'date-fns';

import { derSerializePublicKey } from '../utils/keys/serialisation.js';
import Certificate from '../utils/x509/Certificate.js';
import { getBasicConstraintsExtension } from '../../testUtils/pkijs.js';
import { MEMBER_KEY_PAIR, MEMBER_NAME } from '../../testUtils/veraStubs/member.js';
import { ORG_KEY_PAIR } from '../../testUtils/veraStubs/organisation.js';
import { generateMemberIdFixture } from '../../testUtils/veraStubs/memberIdFixture.js';

import { issueMemberCertificate } from './member.js';

const NOW = setMilliseconds(new Date(), 0);
const START_DATE = subMinutes(NOW, 5);
const EXPIRY_DATE = addMinutes(NOW, 5);

const { organisationCertificate } = await generateMemberIdFixture();

describe('issueMemberCertificate', () => {
  describe('Common Name', () => {
    test('should be the at sign if member is a bot', async () => {
      const serialisation = await issueMemberCertificate(
        undefined,
        MEMBER_KEY_PAIR.publicKey,
        organisationCertificate,
        ORG_KEY_PAIR.privateKey,
        EXPIRY_DATE,
      );

      const certificate = Certificate.deserialize(serialisation);
      expect(certificate.commonName).toBe('@');
    });

    test('should be the specified name if set', async () => {
      const serialisation = await issueMemberCertificate(
        MEMBER_NAME,
        MEMBER_KEY_PAIR.publicKey,
        organisationCertificate,
        ORG_KEY_PAIR.privateKey,
        EXPIRY_DATE,
      );

      const certificate = Certificate.deserialize(serialisation);
      expect(certificate.commonName).toBe(MEMBER_NAME);
    });
  });

  test('Member public key should be honoured', async () => {
    const serialisation = await issueMemberCertificate(
      MEMBER_NAME,
      MEMBER_KEY_PAIR.publicKey,
      organisationCertificate,
      ORG_KEY_PAIR.privateKey,
      EXPIRY_DATE,
    );

    const certificate = Certificate.deserialize(serialisation);
    await expect(derSerializePublicKey(await certificate.getPublicKey())).resolves.toStrictEqual(
      await derSerializePublicKey(MEMBER_KEY_PAIR.publicKey),
    );
  });

  test('Certificate should be issued by organisation', async () => {
    const serialisation = await issueMemberCertificate(
      MEMBER_NAME,
      MEMBER_KEY_PAIR.publicKey,
      organisationCertificate,
      ORG_KEY_PAIR.privateKey,
      EXPIRY_DATE,
    );

    const memberCertificate = Certificate.deserialize(serialisation);
    const orgCertificateDeserialised = Certificate.deserialize(organisationCertificate);
    await expect(
      memberCertificate.getCertificationPath([], [orgCertificateDeserialised]),
    ).resolves.toHaveLength(2);
  });

  test('Expiry date should match specified one', async () => {
    const serialisation = await issueMemberCertificate(
      MEMBER_NAME,
      MEMBER_KEY_PAIR.publicKey,
      organisationCertificate,
      ORG_KEY_PAIR.privateKey,
      EXPIRY_DATE,
    );

    const certificate = Certificate.deserialize(serialisation);
    expect(certificate.validityPeriod.end).toStrictEqual(EXPIRY_DATE);
  });

  describe('Start date', () => {
    test('should default to now', async () => {
      const preIssuanceDate = new Date();

      const serialisation = await issueMemberCertificate(
        MEMBER_NAME,
        MEMBER_KEY_PAIR.publicKey,
        organisationCertificate,
        ORG_KEY_PAIR.privateKey,
        EXPIRY_DATE,
      );

      const certificate = Certificate.deserialize(serialisation);
      expect(certificate.validityPeriod.start).toBeBetween(
        setMilliseconds(preIssuanceDate, 0),
        new Date(),
      );
    });

    test('should match explicit date if set', async () => {
      const serialisation = await issueMemberCertificate(
        MEMBER_NAME,
        MEMBER_KEY_PAIR.publicKey,
        organisationCertificate,
        ORG_KEY_PAIR.privateKey,
        EXPIRY_DATE,
        { startDate: START_DATE },
      );

      const certificate = Certificate.deserialize(serialisation);
      expect(certificate.validityPeriod.start).toStrictEqual(START_DATE);
    });
  });

  describe('Basic constraints extension', () => {
    test('Subject should not be a CA', async () => {
      const serialisation = await issueMemberCertificate(
        MEMBER_NAME,
        MEMBER_KEY_PAIR.publicKey,
        organisationCertificate,
        ORG_KEY_PAIR.privateKey,
        EXPIRY_DATE,
      );

      const certificate = Certificate.deserialize(serialisation);
      const basicConstraints = getBasicConstraintsExtension(certificate.pkijsCertificate);
      expect(basicConstraints.cA).toBeFalse();
    });

    test('Path length should be zero', async () => {
      const serialisation = await issueMemberCertificate(
        MEMBER_NAME,
        MEMBER_KEY_PAIR.publicKey,
        organisationCertificate,
        ORG_KEY_PAIR.privateKey,
        EXPIRY_DATE,
      );

      const certificate = Certificate.deserialize(serialisation);
      const basicConstraints = getBasicConstraintsExtension(certificate.pkijsCertificate);
      expect(basicConstraints.pathLenConstraint).toBe(0);
    });
  });
});
