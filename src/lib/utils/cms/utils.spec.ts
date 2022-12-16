import { Null } from 'asn1js';

import { expectFunctionToThrowError } from '../../../testUtils/errors.js';

import { deserializeContentInfo } from './utils.js';
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
});
