import { addSeconds } from 'date-fns';

import {
  issueMemberCertificate,
  retrieveVeraDnssecChain,
  selfIssueOrganisationCertificate,
  serialiseMemberIdBundle,
  sign,
  verify,
} from '../index.js';
import { MEMBER_KEY_PAIR, MEMBER_NAME } from '../testUtils/veraStubs/member.js';
import { arrayBufferFrom } from '../testUtils/buffers.js';
import { VERA_OIDS } from '../lib/oids.js';
import VeraError from '../lib/VeraError.js';
import { generateRsaKeyPair } from '../lib/utils/keys/generation.js';

import { TEST_ORG_KEY_PAIR, TEST_ORG_NAME } from './utils.js';
import { resolveWithRetries } from './resolver.js';

const EXPIRY_DATE = addSeconds(new Date(), 60);
const ORG_CERTIFICATE = await selfIssueOrganisationCertificate(
  TEST_ORG_NAME,
  TEST_ORG_KEY_PAIR,
  EXPIRY_DATE,
);
const MEMBER_CERTIFICATE = await issueMemberCertificate(
  MEMBER_NAME,
  MEMBER_KEY_PAIR.publicKey,
  ORG_CERTIFICATE,
  TEST_ORG_KEY_PAIR.privateKey,
  EXPIRY_DATE,
);

const PLAINTEXT = arrayBufferFrom('This is the plaintext');

describe('main', () => {
  test('Valid signature bundle', async () => {
    const chain = await retrieveVeraDnssecChain(TEST_ORG_NAME, undefined, resolveWithRetries);
    const memberIdBundle = serialiseMemberIdBundle(MEMBER_CERTIFICATE, ORG_CERTIFICATE, chain);
    const signatureBundle = await sign(
      PLAINTEXT,
      VERA_OIDS.TEST_SERVICE,
      memberIdBundle,
      MEMBER_KEY_PAIR.privateKey,
      EXPIRY_DATE,
    );

    const { organisation, user } = await verify(PLAINTEXT, signatureBundle, VERA_OIDS.TEST_SERVICE);

    expect(organisation).toStrictEqual(TEST_ORG_NAME);
    expect(user).toStrictEqual(MEMBER_NAME);
  });

  test('Invalid signature', async () => {
    const chain = await retrieveVeraDnssecChain(TEST_ORG_NAME, undefined, resolveWithRetries);
    const memberIdBundle = serialiseMemberIdBundle(MEMBER_CERTIFICATE, ORG_CERTIFICATE, chain);
    const otherMemberKeyPair = await generateRsaKeyPair();
    const signatureBundle = await sign(
      PLAINTEXT,
      VERA_OIDS.TEST_SERVICE,
      memberIdBundle,
      otherMemberKeyPair.privateKey,
      EXPIRY_DATE,
    );

    await expect(async () =>
      verify(PLAINTEXT, signatureBundle, VERA_OIDS.TEST_SERVICE),
    ).rejects.toThrow(VeraError);
  });
});
