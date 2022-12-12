import { ContentInfo, type PkiObject, type PkiObjectParameters } from 'pkijs';

import { derDeserialize } from '../utils.js';

import CmsError from './CmsError.js';

export function deserializeContentInfo(derValue: ArrayBuffer): ContentInfo {
  try {
    const asn1Value = derDeserialize(derValue);
    return new ContentInfo({ schema: asn1Value });
  } catch (err) {
    throw new CmsError('Could not deserialize CMS ContentInfo', { cause: err });
  }
}

interface PkiObjectConstructor<T extends PkiObject = PkiObject> {
  new (params: PkiObjectParameters): T;
  readonly CLASS_NAME: string;
}

/**
 * Check that incoming object is instance of supplied type.
 */
export function assertPkiType<T extends PkiObject>(
  object: unknown,
  type: PkiObjectConstructor<T>,
  targetName: string,
): asserts object is T {
  if (!(object && object instanceof type)) {
    throw new TypeError(`Incorrect type of '${targetName}'. It should be '${type.CLASS_NAME}'`);
  }
}

export function assertUndefined(data: unknown, paramName?: string): asserts data {
  if (data === undefined) {
    throw new Error(`Required parameter ${paramName ? `'${paramName}'` : paramName} is missing`);
  }
}
