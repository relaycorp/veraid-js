import { jest } from '@jest/globals';
import { addMinutes, setMilliseconds, subMinutes } from 'date-fns';

import { derSerializePublicKey } from '../utils/keys.js';
import type FullIssuanceOptions from '../utils/x509/FullIssuanceOptions.js';
import Certificate from '../utils/x509/Certificate.js';
import { getBasicConstraintsExtension } from '../../testUtils/pkijs.js';
import { ORG_KEY_PAIR, ORG_NAME } from '../../testUtils/veraStubs/organisation.js';

import { selfIssueOrganisationCertificate } from './organisation.js';

const NOW = setMilliseconds(new Date(), 0);
const START_DATE = subMinutes(NOW, 5);
const EXPIRY_DATE = addMinutes(NOW, 5);

describe('selfIssueOrganisationCertificate', () => {
  test('Name should be used as Common Name', async () => {
    const serialisation = await selfIssueOrganisationCertificate(
      ORG_NAME,
      ORG_KEY_PAIR,
      EXPIRY_DATE,
    );

    const certificate = Certificate.deserialize(serialisation);
    expect(certificate.commonName).toStrictEqual(ORG_NAME);
  });

  test('Subject public key should be honoured', async () => {
    const serialisation = await selfIssueOrganisationCertificate(
      ORG_NAME,
      ORG_KEY_PAIR,
      EXPIRY_DATE,
    );

    const certificate = Certificate.deserialize(serialisation);
    await expect(derSerializePublicKey(await certificate.getPublicKey())).resolves.toStrictEqual(
      await derSerializePublicKey(ORG_KEY_PAIR.publicKey),
    );
  });

  test('Certificate should be signed with private key', async () => {
    const certificateIssueSpy = jest.spyOn(Certificate, 'issue');

    await selfIssueOrganisationCertificate(ORG_NAME, ORG_KEY_PAIR, EXPIRY_DATE);

    expect(certificateIssueSpy).toHaveBeenCalledWith(
      expect.objectContaining<Partial<FullIssuanceOptions>>({
        issuerPrivateKey: ORG_KEY_PAIR.privateKey,
      }),
    );
  });

  test('Expiry date should match specified one', async () => {
    const serialisation = await selfIssueOrganisationCertificate(
      ORG_NAME,
      ORG_KEY_PAIR,
      EXPIRY_DATE,
    );

    const certificate = Certificate.deserialize(serialisation);
    expect(certificate.expiryDate).toStrictEqual(EXPIRY_DATE);
  });

  describe('Start date', () => {
    test('should default to now', async () => {
      const preIssuanceDate = new Date();

      const serialisation = await selfIssueOrganisationCertificate(
        ORG_NAME,
        ORG_KEY_PAIR,
        EXPIRY_DATE,
      );

      const certificate = Certificate.deserialize(serialisation);
      expect(certificate.startDate).toBeBetween(setMilliseconds(preIssuanceDate, 0), new Date());
    });

    test('should match explicit date if set', async () => {
      const serialisation = await selfIssueOrganisationCertificate(
        ORG_NAME,
        ORG_KEY_PAIR,
        EXPIRY_DATE,
        {
          startDate: START_DATE,
        },
      );

      const certificate = Certificate.deserialize(serialisation);
      expect(certificate.startDate).toStrictEqual(START_DATE);
    });
  });

  describe('Basic constraints extension', () => {
    test('Subject should be a CA', async () => {
      const serialisation = await selfIssueOrganisationCertificate(
        ORG_NAME,
        ORG_KEY_PAIR,
        EXPIRY_DATE,
        {
          startDate: START_DATE,
        },
      );

      const certificate = Certificate.deserialize(serialisation);
      const basicConstraints = getBasicConstraintsExtension(certificate.pkijsCertificate);
      expect(basicConstraints.cA).toBeTrue();
    });

    test('Path length should be zero', async () => {
      const serialisation = await selfIssueOrganisationCertificate(
        ORG_NAME,
        ORG_KEY_PAIR,
        EXPIRY_DATE,
        {
          startDate: START_DATE,
        },
      );

      const certificate = Certificate.deserialize(serialisation);
      const basicConstraints = getBasicConstraintsExtension(certificate.pkijsCertificate);
      expect(basicConstraints.pathLenConstraint).toBe(0);
    });
  });
});
