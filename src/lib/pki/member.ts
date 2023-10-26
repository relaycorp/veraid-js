import Certificate from '../utils/x509/Certificate.js';
import VeraError from '../VeraError.js';

import type { CertificateIssuanceOptions } from './CertificateIssuanceOptions.js';

const FORBIDDEN_USER_NAME_CHARS_REGEX = /[@\t\r\n]/u;

/**
 * Check whether the `userName` contains illegal characters.
 * @param userName The username to check.
 * @throws {VeraError} if `userName` contains illegal characters.
 */
export function validateUserName(userName: string) {
  if (FORBIDDEN_USER_NAME_CHARS_REGEX.test(userName)) {
    throw new VeraError(
      'User name should not contain at signs or whitespace other than simple spaces',
    );
  }
}

export const BOT_NAME = '@';

export async function issueMemberCertificate(
  memberName: string | undefined,
  memberPublicKey: CryptoKey,
  organisationCertificate: ArrayBuffer,
  organisationPrivateKey: CryptoKey,
  expiryDate: Date,
  options: Partial<CertificateIssuanceOptions> = {},
): Promise<ArrayBuffer> {
  if (memberName !== undefined) {
    validateUserName(memberName);
  }

  const issuerCertificate = Certificate.deserialize(organisationCertificate);
  const certificate = await Certificate.issue({
    commonName: memberName ?? BOT_NAME,
    subjectPublicKey: memberPublicKey,
    issuerCertificate,
    issuerPrivateKey: organisationPrivateKey,
    validityEndDate: expiryDate,
    validityStartDate: options.startDate,
  });
  return certificate.serialize();
}
