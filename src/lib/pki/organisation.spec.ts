import { jest } from '@jest/globals';
import { addMinutes, setMilliseconds, subMinutes } from 'date-fns';

import { derSerializePublicKey } from '../utils/keys/serialisation.js';
import type FullIssuanceOptions from '../utils/x509/FullIssuanceOptions.js';
import { Certificate } from '../utils/x509/Certificate.js';
import { getBasicConstraintsExtension } from '../../testUtils/pkijs.js';
import { ORG_KEY_PAIR, ORG_NAME } from '../../testUtils/veraStubs/organisation.js';

import { selfIssueOrganisationCertificate } from './organisation.js';

const NOW = setMilliseconds(new Date(), 0);
const START_DATE = subMinutes(NOW, 5);
const EXPIRY_DATE = addMinutes(NOW, 5);

describe('selfIssueOrganisationCertificate', () => {
  test('Common name should match specified one', async () => {
    const certificate = await selfIssueOrganisationCertificate(ORG_NAME, ORG_KEY_PAIR, EXPIRY_DATE);

    expect(certificate.commonName).toBe(ORG_NAME);
  });

  test('Public key should match specified one', async () => {
    const certificate = await selfIssueOrganisationCertificate(ORG_NAME, ORG_KEY_PAIR, EXPIRY_DATE);

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
    const certificate = await selfIssueOrganisationCertificate(ORG_NAME, ORG_KEY_PAIR, EXPIRY_DATE);

    expect(certificate.validityPeriod.end).toStrictEqual(EXPIRY_DATE);
  });

  describe('Start date', () => {
    test('should default to now', async () => {
      const preIssuanceDate = new Date();

      const certificate = await selfIssueOrganisationCertificate(
        ORG_NAME,
        ORG_KEY_PAIR,
        EXPIRY_DATE,
      );

      expect(certificate.validityPeriod.start).toBeBetween(
        setMilliseconds(preIssuanceDate, 0),
        new Date(),
      );
    });

    test('should match explicit date if set', async () => {
      const certificate = await selfIssueOrganisationCertificate(
        ORG_NAME,
        ORG_KEY_PAIR,
        EXPIRY_DATE,
        { startDate: START_DATE },
      );

      expect(certificate.validityPeriod.start).toStrictEqual(START_DATE);
    });
  });

  describe('Basic constraints extension', () => {
    test('Subject should be a CA', async () => {
      const certificate = await selfIssueOrganisationCertificate(
        ORG_NAME,
        ORG_KEY_PAIR,
        EXPIRY_DATE,
        {
          startDate: START_DATE,
        },
      );

      const basicConstraints = getBasicConstraintsExtension(certificate.pkijsCertificate);
      expect(basicConstraints.cA).toBeTrue();
    });

    test('Path length should be zero', async () => {
      const certificate = await selfIssueOrganisationCertificate(
        ORG_NAME,
        ORG_KEY_PAIR,
        EXPIRY_DATE,
        {
          startDate: START_DATE,
        },
      );

      const basicConstraints = getBasicConstraintsExtension(certificate.pkijsCertificate);
      expect(basicConstraints.pathLenConstraint).toBe(0);
    });
  });
});
