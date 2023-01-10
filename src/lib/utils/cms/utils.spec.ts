import { Null, OctetString } from 'asn1js';
import { ContentInfo } from 'pkijs';

import { expectFunctionToThrowError } from '../../../testUtils/errors.js';
import { arrayBufferFrom } from '../../../testUtils/buffers.js';

import { deserializeContentInfo } from './utils.js';
import CmsError from './CmsError.js';

describe('CMS utils', () => {
  describe('deserializeContentInfo', () => {
    test('Malformed ANS.1 DER value should be refused', () => {
      const serialisation = Buffer.from([0]);

      expectFunctionToThrowError(
        () => deserializeContentInfo(serialisation),
        new CmsError('Could not deserialize CMS ContentInfo', { cause: expect.anything() }),
      );
    });

    test('Malformed ContentInfo should be refused', () => {
      const serialisation = new Null().toBER();

      expectFunctionToThrowError(
        () => deserializeContentInfo(serialisation),
        new CmsError('Could not deserialize CMS ContentInfo', { cause: expect.anything() }),
      );
    });

    test('Well-formed ContentInfo should be output', () => {
      const content = new OctetString({ valueHex: arrayBufferFrom('foo') });
      const contentInfo = new ContentInfo({ content, contentType: 'the type' });
      const serialisation = contentInfo.toSchema().toBER();

      const contentInfoDeserialised = deserializeContentInfo(serialisation);

      expect(contentInfoDeserialised.toString('hex')).toStrictEqual(contentInfo.toString('hex'));
    });
  });
});
