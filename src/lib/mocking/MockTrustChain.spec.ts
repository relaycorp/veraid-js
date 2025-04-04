import { addSeconds, setMilliseconds, subSeconds } from 'date-fns';

import { arrayBufferFrom } from '../../testUtils/buffers.js';
import { MEMBER_NAME } from '../../testUtils/veraStubs/member.js';
import { ORG_NAME } from '../../testUtils/veraStubs/organisation.js';
import { VERAID_OIDS } from '../oids.js';

import { MockTrustChain } from './MockTrustChain.js';

const PLAINTEXT = arrayBufferFrom('The plaintext');

describe('MockTrustChain', () => {
  describe('sign', () => {
    test('should attribute signature bundle to correct organisation', async () => {
      const mockTrustChain = await MockTrustChain.generate(
        ORG_NAME,
        MEMBER_NAME,
        addSeconds(new Date(), 10),
      );

      const signatureBundle = await mockTrustChain.sign(PLAINTEXT, VERAID_OIDS.TEST_SERVICE);

      const { member } = await signatureBundle.verify(
        undefined,
        VERAID_OIDS.TEST_SERVICE,
        new Date(),
        mockTrustChain.dnssecTrustAnchors,
      );
      expect(member.organisation).toBe(ORG_NAME);
    });

    test('should attribute signature bundle to correct member when it is a user', async () => {
      const mockTrustChain = await MockTrustChain.generate(
        ORG_NAME,
        MEMBER_NAME,
        addSeconds(new Date(), 10),
      );

      const signatureBundle = await mockTrustChain.sign(PLAINTEXT, VERAID_OIDS.TEST_SERVICE);

      const { member } = await signatureBundle.verify(
        undefined,
        VERAID_OIDS.TEST_SERVICE,
        new Date(),
        mockTrustChain.dnssecTrustAnchors,
      );
      expect(member.user).toBe(MEMBER_NAME);
    });

    test('should attribute signature bundle to no user when it is a bot', async () => {
      const mockTrustChain = await MockTrustChain.generate(
        ORG_NAME,
        undefined,
        addSeconds(new Date(), 10),
      );

      const signatureBundle = await mockTrustChain.sign(PLAINTEXT, VERAID_OIDS.TEST_SERVICE);

      const { member } = await signatureBundle.verify(
        undefined,
        VERAID_OIDS.TEST_SERVICE,
        new Date(),
        mockTrustChain.dnssecTrustAnchors,
      );
      expect(member.user).toBeUndefined();
    });

    test('should use member signature when requested', async () => {
      const mockTrustChain = await MockTrustChain.generate(
        ORG_NAME,
        MEMBER_NAME,
        addSeconds(new Date(), 10),
      );

      const signatureBundle = await mockTrustChain.sign(PLAINTEXT, VERAID_OIDS.TEST_SERVICE);

      const { wasSignedByMember } = await signatureBundle.verify(
        undefined,
        VERAID_OIDS.TEST_SERVICE,
        new Date(),
        mockTrustChain.dnssecTrustAnchors,
      );
      expect(wasSignedByMember).toBe(true);
    });

    test('should use organisation signature when requested', async () => {
      const mockTrustChain = await MockTrustChain.generate(
        ORG_NAME,
        undefined,
        addSeconds(new Date(), 10),
        { shouldBeSignedByMember: false },
      );

      const signatureBundle = await mockTrustChain.sign(PLAINTEXT, VERAID_OIDS.TEST_SERVICE);

      const { wasSignedByMember } = await signatureBundle.verify(
        undefined,
        VERAID_OIDS.TEST_SERVICE,
        new Date(),
        mockTrustChain.dnssecTrustAnchors,
      );
      expect(wasSignedByMember).toBe(false);
    });

    test('should use specified expiry date', async () => {
      const expiryDate = setMilliseconds(addSeconds(new Date(), 10), 0);
      const mockTrustChain = await MockTrustChain.generate(ORG_NAME, MEMBER_NAME, expiryDate);

      const signatureBundle = await mockTrustChain.sign(PLAINTEXT, VERAID_OIDS.TEST_SERVICE);

      await expect(
        signatureBundle.verify(
          undefined,
          VERAID_OIDS.TEST_SERVICE,
          expiryDate,
          mockTrustChain.dnssecTrustAnchors,
        ),
      ).toResolve();
      await expect(
        signatureBundle.verify(
          undefined,
          VERAID_OIDS.TEST_SERVICE,
          addSeconds(expiryDate, 1),
          mockTrustChain.dnssecTrustAnchors,
        ),
      ).toReject();
    });

    test('should use current date as start by default', async () => {
      const startDate = new Date();
      const mockTrustChain = await MockTrustChain.generate(
        ORG_NAME,
        MEMBER_NAME,
        addSeconds(startDate, 10),
      );

      const signatureBundle = await mockTrustChain.sign(PLAINTEXT, VERAID_OIDS.TEST_SERVICE);

      await expect(
        signatureBundle.verify(
          undefined,
          VERAID_OIDS.TEST_SERVICE,
          addSeconds(startDate, 1),
          mockTrustChain.dnssecTrustAnchors,
        ),
      ).toResolve();
      await expect(
        signatureBundle.verify(
          undefined,
          VERAID_OIDS.TEST_SERVICE,
          subSeconds(startDate, 1),
          mockTrustChain.dnssecTrustAnchors,
        ),
      ).toReject();
    });

    test('should use custom start date if specified', async () => {
      const startDate = setMilliseconds(new Date(), 0);
      const mockTrustChain = await MockTrustChain.generate(
        ORG_NAME,
        MEMBER_NAME,
        addSeconds(startDate, 10),
        { startDate },
      );

      const signatureBundle = await mockTrustChain.sign(PLAINTEXT, VERAID_OIDS.TEST_SERVICE);

      await expect(
        signatureBundle.verify(
          undefined,
          VERAID_OIDS.TEST_SERVICE,
          startDate,
          mockTrustChain.dnssecTrustAnchors,
        ),
      ).toResolve();
      await expect(
        signatureBundle.verify(
          undefined,
          VERAID_OIDS.TEST_SERVICE,
          subSeconds(startDate, 1),
          mockTrustChain.dnssecTrustAnchors,
        ),
      ).toReject();
    });

    test('should encapsulate plaintext by default', async () => {
      const mockTrustChain = await MockTrustChain.generate(
        ORG_NAME,
        MEMBER_NAME,
        addSeconds(new Date(), 10),
      );

      const signatureBundle = await mockTrustChain.sign(PLAINTEXT, VERAID_OIDS.TEST_SERVICE);

      const { plaintext } = await signatureBundle.verify(
        undefined,
        VERAID_OIDS.TEST_SERVICE,
        new Date(),
        mockTrustChain.dnssecTrustAnchors,
      );
      expect(Buffer.from(plaintext).equals(Buffer.from(PLAINTEXT))).toBeTrue();
    });

    test('should not encapsulate plaintext if requested', async () => {
      const mockTrustChain = await MockTrustChain.generate(
        ORG_NAME,
        MEMBER_NAME,
        addSeconds(new Date(), 10),
      );

      const signatureBundle = await mockTrustChain.sign(PLAINTEXT, VERAID_OIDS.TEST_SERVICE, false);

      const { plaintext } = await signatureBundle.verify(
        PLAINTEXT,
        VERAID_OIDS.TEST_SERVICE,
        new Date(),
        mockTrustChain.dnssecTrustAnchors,
      );
      expect(Buffer.from(plaintext).equals(Buffer.from(PLAINTEXT))).toBeTrue();
    });
  });
});
