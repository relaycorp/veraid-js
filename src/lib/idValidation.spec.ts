import { MEMBER_NAME } from '../testUtils/veraStubs/member.js';

import VeraidError from './VeraidError.js';
import { validateUserName } from './idValidation.js';

describe('validateUserName', () => {
  const validationErrorMessage =
    'User name should not contain at signs or whitespace other than simple spaces';

  test('Well-formed name should be allowed', () => {
    expect(() => {
      validateUserName(MEMBER_NAME);
    }).not.toThrow();
  });

  test('Name should not contain at signs', () => {
    expect(() => {
      validateUserName('@');
    }).toThrowWithMessage(VeraidError, validationErrorMessage);
  });

  test('Name should not contain tabs', () => {
    expect(() => {
      validateUserName(`\t${MEMBER_NAME}`);
    }).toThrowWithMessage(VeraidError, validationErrorMessage);
  });

  test('Name should not contain carriage returns', () => {
    expect(() => {
      validateUserName(`\r${MEMBER_NAME}`);
    }).toThrowWithMessage(VeraidError, validationErrorMessage);
  });

  test('Name should not contain line feeds', () => {
    expect(() => {
      validateUserName(`\n${MEMBER_NAME}`);
    }).toThrowWithMessage(VeraidError, validationErrorMessage);
  });
});
