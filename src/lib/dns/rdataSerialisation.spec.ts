import { secondsInDay } from 'date-fns';

import VeraError from '../VeraError.js';
import {
  ORG_KEY_PAIR,
  ORG_KEY_SPEC,
  VERA_RECORD_TTL_OVERRIDE,
} from '../../testUtils/veraStubs/organisation.js';
import { SERVICE_OID } from '../../testUtils/veraStubs/service.js';

import { generateTxtRdata, parseTxtRdata } from './rdataSerialisation.js';
import { KeyAlgorithmType } from './KeyAlgorithmType.js';
import type { VeraRdataFields } from './VeraRdataFields.js';

describe('generateTxtRdata', () => {
  function splitAndGetField(rdata: string, index: number): string | undefined {
    return rdata.split(' ')[index];
  }

  test('Key algorithm and id should be defined correctly', async () => {
    const rdata = await generateTxtRdata(ORG_KEY_PAIR.publicKey, VERA_RECORD_TTL_OVERRIDE);

    const algorithm = splitAndGetField(rdata, 0);
    expect(algorithm).toStrictEqual(ORG_KEY_SPEC.keyAlgorithm.toString());
    const digest = splitAndGetField(rdata, 1);
    expect(digest).toStrictEqual(ORG_KEY_SPEC.keyId);
  });

  describe('TTL override', () => {
    test('Negative values should be refused', async () => {
      const invalidTtlOverride = -1;
      await expect(async () =>
        generateTxtRdata(ORG_KEY_PAIR.publicKey, invalidTtlOverride),
      ).rejects.toThrowWithMessage(
        VeraError,
        `TTL override must not be negative (got ${invalidTtlOverride})`,
      );
    });

    test('Zero should be allowed', async () => {
      const rdata = await generateTxtRdata(ORG_KEY_PAIR.publicKey, 0);

      const ttl = splitAndGetField(rdata, 2);
      expect(ttl).toBe('0');
    });

    test('Positive values should be allowed', async () => {
      const ttlOverride = 1;
      const rdata = await generateTxtRdata(ORG_KEY_PAIR.publicKey, ttlOverride);

      const ttl = splitAndGetField(rdata, 2);
      expect(ttl).toBe(ttlOverride.toString());
    });

    test('90 days should be allowed', async () => {
      const ttlOverride = secondsInDay * 90;
      const rdata = await generateTxtRdata(ORG_KEY_PAIR.publicKey, ttlOverride);

      const ttl = splitAndGetField(rdata, 2);
      expect(ttl).toBe(ttlOverride.toString());
    });

    test('More than 90 days should be refused', async () => {
      const invalidTtlOverride = secondsInDay * 90 + 1;
      await expect(
        generateTxtRdata(ORG_KEY_PAIR.publicKey, invalidTtlOverride),
      ).rejects.toThrowWithMessage(
        VeraError,
        `TTL override must not exceed 90 days (got ${invalidTtlOverride} seconds)`,
      );
    });
  });

  describe('Service', () => {
    test('No service should be specified by default', async () => {
      const rdata = await generateTxtRdata(ORG_KEY_PAIR.publicKey, VERA_RECORD_TTL_OVERRIDE);

      const service = splitAndGetField(rdata, 4);
      expect(service).toBeUndefined();
    });

    test('Service should be specified if set', async () => {
      const rdata = await generateTxtRdata(
        ORG_KEY_PAIR.publicKey,
        VERA_RECORD_TTL_OVERRIDE,
        SERVICE_OID,
      );

      const service = splitAndGetField(rdata, 3);
      expect(service).toStrictEqual(SERVICE_OID);
    });
  });
});

describe('parseTxtRdata', () => {
  const algorithmId = KeyAlgorithmType.RSA_2048;

  test('There should be at least 3 space-separated fields', () => {
    const malformedRdata = 'one two';

    expect(() => parseTxtRdata(malformedRdata)).toThrowWithMessage(
      VeraError,
      'RDATA should have at least 3 space-separated fields (got 2)',
    );
  });

  test('Invalid key algorithm should be refused', () => {
    const invalidAlgorithmId = 4;
    const rdata = `${invalidAlgorithmId} ${ORG_KEY_SPEC.keyId} ${VERA_RECORD_TTL_OVERRIDE}`;

    expect(() => parseTxtRdata(rdata)).toThrowWithMessage(
      VeraError,
      `Unknown algorithm id ("${invalidAlgorithmId}")`,
    );
  });

  describe('TTL override validation', () => {
    const ninetyDaysInSeconds = secondsInDay * 90;

    test('Non-integer value should be refused', () => {
      const invalidTtlOverride = 4.5;
      const rdata = `${algorithmId} ${ORG_KEY_SPEC.keyId} ${invalidTtlOverride}`;

      expect(() => parseTxtRdata(rdata)).toThrowWithMessage(
        VeraError,
        `Malformed TTL override ("${invalidTtlOverride}")`,
      );
    });

    test('Negative value should be refused', () => {
      const invalidTtlOverride = -4;
      const rdata = `${algorithmId} ${ORG_KEY_SPEC.keyId} ${invalidTtlOverride}`;

      expect(() => parseTxtRdata(rdata)).toThrowWithMessage(
        VeraError,
        `Malformed TTL override ("${invalidTtlOverride}")`,
      );
    });

    test('90 days should be allowed', () => {
      const rdata = `${algorithmId} ${ORG_KEY_SPEC.keyId} ${ninetyDaysInSeconds}`;

      const fields = parseTxtRdata(rdata);

      expect(fields.ttlOverride).toStrictEqual(ninetyDaysInSeconds);
    });

    test('TTL should be capped at 90 days', () => {
      const rdata = `${algorithmId} ${ORG_KEY_SPEC.keyId} ${ninetyDaysInSeconds + 1}`;

      const fields = parseTxtRdata(rdata);

      expect(fields.ttlOverride).toStrictEqual(ninetyDaysInSeconds);
    });
  });

  test('Fields should be output if value is valid', () => {
    const rdata = `${algorithmId} ${ORG_KEY_SPEC.keyId} ${VERA_RECORD_TTL_OVERRIDE}`;

    const fields = parseTxtRdata(rdata);

    expect(fields).toMatchObject<Partial<VeraRdataFields>>({
      keyAlgorithm: algorithmId,
      keyId: ORG_KEY_SPEC.keyId,
      ttlOverride: VERA_RECORD_TTL_OVERRIDE,
    });
  });

  test('Service OID should be absent if unspecified', () => {
    const rdata = `${algorithmId} ${ORG_KEY_SPEC.keyId} ${VERA_RECORD_TTL_OVERRIDE}`;

    const fields = parseTxtRdata(rdata);

    expect(fields.serviceOid).toBeUndefined();
  });

  test('Service OID should be present if specified', () => {
    const rdata = `${algorithmId} ${ORG_KEY_SPEC.keyId} ${VERA_RECORD_TTL_OVERRIDE} ${SERVICE_OID}`;

    const fields = parseTxtRdata(rdata);

    expect(fields.serviceOid).toStrictEqual(SERVICE_OID);
  });

  describe('Input type', () => {
    const rdataString = `${algorithmId} ${ORG_KEY_SPEC.keyId} ${VERA_RECORD_TTL_OVERRIDE}`;
    const expectedFields: Partial<VeraRdataFields> = {
      keyAlgorithm: algorithmId,
      keyId: ORG_KEY_SPEC.keyId,
      ttlOverride: VERA_RECORD_TTL_OVERRIDE,
    };

    test('Buffer input should be supported', () => {
      const rdata = Buffer.from(rdataString);

      const fields = parseTxtRdata(rdata);

      expect(fields).toMatchObject<Partial<VeraRdataFields>>({
        keyAlgorithm: algorithmId,
        keyId: ORG_KEY_SPEC.keyId,
        ttlOverride: VERA_RECORD_TTL_OVERRIDE,
      });
    });

    test('Array of single buffer input should be supported', () => {
      const rdata = [Buffer.from(rdataString)];

      const fields = parseTxtRdata(rdata);

      expect(fields).toMatchObject<Partial<VeraRdataFields>>(expectedFields);
    });

    test('Empty array should not be supported', () => {
      expect(() => parseTxtRdata([])).toThrowWithMessage(
        VeraError,
        'TXT rdata array must contain a single item (got 0)',
      );
    });

    test('Array of multiple items should not be supported', () => {
      const rdata = [Buffer.from(rdataString), Buffer.from(rdataString)];

      expect(() => parseTxtRdata(rdata)).toThrowWithMessage(
        VeraError,
        'TXT rdata array must contain a single item (got 2)',
      );
    });
  });

  describe('Extraneous whitespace tolerance', () => {
    let expectedFields: VeraRdataFields;
    beforeAll(() => {
      expectedFields = {
        keyAlgorithm: algorithmId,
        keyId: ORG_KEY_SPEC.keyId,
        ttlOverride: VERA_RECORD_TTL_OVERRIDE,
        serviceOid: undefined,
      };
    });

    test('Leading whitespace should be ignored', () => {
      const rdata = ` \t ${algorithmId} ${ORG_KEY_SPEC.keyId} ${VERA_RECORD_TTL_OVERRIDE}`;

      expect(parseTxtRdata(rdata)).toStrictEqual(expectedFields);
    });

    test('Trailing whitespace should be ignored', () => {
      const rdata = `${algorithmId} ${ORG_KEY_SPEC.keyId} ${VERA_RECORD_TTL_OVERRIDE} \t `;

      expect(parseTxtRdata(rdata)).toStrictEqual(expectedFields);
    });

    test('Extra whitespace in separator should be ignored', () => {
      const rdata = `${algorithmId} \t   ${ORG_KEY_SPEC.keyId} ${VERA_RECORD_TTL_OVERRIDE}`;

      expect(parseTxtRdata(rdata)).toStrictEqual(expectedFields);
    });
  });
});
