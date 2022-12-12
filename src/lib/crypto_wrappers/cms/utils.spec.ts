import { Null } from 'asn1js';
import { CertID, Certificate } from 'pkijs';

import { expectFunctionToThrowError } from '../../../testUtils/errors.js';

import { assertPkiType, assertUndefined, deserializeContentInfo } from './utils.js';
import CmsError from './CmsError.js';

describe('CMS utils', () => {
  describe('deserializeContentInfo', () => {
    test('Malformed ANS.1 DER value should be refused', () => {
      const malformed = Buffer.from([0]);

      expectFunctionToThrowError(
        () => deserializeContentInfo(malformed),
        new CmsError('Could not deserialize CMS ContentInfo', { cause: expect.anything() }),
      );
    });

    test('Malformed ContentInfo should be refused', () => {
      const malformed = new Null().toBER();

      expectFunctionToThrowError(
        () => deserializeContentInfo(malformed),
        new CmsError('Could not deserialize CMS ContentInfo', { cause: expect.anything() }),
      );
    });

    test.todo('Well-formed ContentInfo should be output');
  });

  describe('assertPkiType', () => {
    test('Correct type should be accepted', () => {
      const cert = new Certificate();

      expect(() => {
        assertPkiType(cert, Certificate, 'test');
      }).not.toThrow();
    });

    test('Incorrect type should be refused', () => {
      const cert = new Certificate();

      expect(() => {
        assertPkiType(cert, CertID, 'test');
      }).toThrowWithMessage(Error, "Incorrect type of 'test'. It should be 'CertId'");
    });
  });

  describe('assertUndefined', () => {
    test('correct', () => {
      const v = false;
      expect(() => {
        assertUndefined(v, 'test');
      }).not.toThrow();
    });

    test('incorrect', () => {
      const o = undefined;

      expect(() => {
        assertUndefined(o);
      }).toThrow(Error);
    });

    test('incorrect with param name', () => {
      const o = undefined;

      expect(() => {
        assertUndefined(o, 'test');
      }).toThrow(Error);
    });
  });
});
