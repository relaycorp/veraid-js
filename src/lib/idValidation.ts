import VeraidError from './VeraidError.js';

const FORBIDDEN_USER_NAME_CHARS_REGEX = /[@\t\r\n]/u;

/**
 * Check whether the `userName` contains illegal characters.
 * @param userName The username to check.
 * @throws {VeraidError} if `userName` contains illegal characters.
 */
export function validateUserName(userName: string) {
  if (FORBIDDEN_USER_NAME_CHARS_REGEX.test(userName)) {
    throw new VeraidError(
      'User name should not contain at signs or whitespace other than simple spaces',
    );
  }
}
