import { addSeconds } from 'date-fns';

import {
  issueMemberCertificate,
  selfIssueOrganisationCertificate,
  MemberIdBundle,
  SignatureBundle,
  VeraidDnssecChain,
  VeraidError,
} from '../index.js';
import { MEMBER_KEY_PAIR, MEMBER_NAME } from '../testUtils/veraStubs/member.js';
import { arrayBufferFrom } from '../testUtils/buffers.js';
import { VERAID_OIDS } from '../lib/oids.js';
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

const DNSSEC_CHAIN = await VeraidDnssecChain.retrieve(TEST_ORG_NAME, {
  resolver: resolveWithRetries,
});
const MEMBER_ID_BUNDLE = new MemberIdBundle(DNSSEC_CHAIN, ORG_CERTIFICATE, MEMBER_CERTIFICATE);

describe('main', () => {
  test('Valid signature bundle', async () => {
    const signatureBundle = await SignatureBundle.sign(
      PLAINTEXT,
      VERAID_OIDS.TEST_SERVICE,
      MEMBER_ID_BUNDLE,
      MEMBER_KEY_PAIR.privateKey,
      EXPIRY_DATE,
    );
    const signatureBundleSerialised = signatureBundle.serialise();
    const bundle = SignatureBundle.deserialise(signatureBundleSerialised);

    const { plaintext, member } = await bundle.verify(PLAINTEXT, VERAID_OIDS.TEST_SERVICE);

    expect(new Uint8Array(plaintext)).toStrictEqual(new Uint8Array(PLAINTEXT));
    expect(member.organisation).toStrictEqual(TEST_ORG_NAME);
    expect(member.user).toStrictEqual(MEMBER_NAME);
  });

  test('Invalid signature', async () => {
    const otherMemberKeyPair = await generateRsaKeyPair();
    const signatureBundle = await SignatureBundle.sign(
      PLAINTEXT,
      VERAID_OIDS.TEST_SERVICE,
      MEMBER_ID_BUNDLE,
      otherMemberKeyPair.privateKey,
      EXPIRY_DATE,
    );
    const signatureBundleSerialised = signatureBundle.serialise();
    const bundle = SignatureBundle.deserialise(signatureBundleSerialised);

    await expect(async () => bundle.verify(PLAINTEXT, VERAID_OIDS.TEST_SERVICE)).rejects.toThrow(
      VeraidError,
    );
  });

  test('Different service', async () => {
    const otherMemberKeyPair = await generateRsaKeyPair();
    const signatureBundle = await SignatureBundle.sign(
      PLAINTEXT,
      VERAID_OIDS.TEST_SERVICE,
      MEMBER_ID_BUNDLE,
      otherMemberKeyPair.privateKey,
      EXPIRY_DATE,
    );
    const signatureBundleSerialised = signatureBundle.serialise();
    const bundle = SignatureBundle.deserialise(signatureBundleSerialised);
    const differentService = `${VERAID_OIDS.TEST_SERVICE}.42`;

    await expect(async () => bundle.verify(PLAINTEXT, differentService)).rejects.toThrow(
      VeraidError,
    );
  });
});
