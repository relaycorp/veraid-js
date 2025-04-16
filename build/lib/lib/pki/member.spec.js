import { addMinutes, setMilliseconds, subMinutes } from 'date-fns';
import { derSerializePublicKey } from '../utils/keys/serialisation.js';
import { getBasicConstraintsExtension } from '../../testUtils/pkijs.js';
import { MEMBER_KEY_PAIR, MEMBER_NAME } from '../../testUtils/veraStubs/member.js';
import { ORG_KEY_PAIR } from '../../testUtils/veraStubs/organisation.js';
import { generateMemberIdFixture } from '../../testUtils/veraStubs/memberIdFixture.js';
import { VeraidError } from '../VeraidError.js';
import { issueMemberCertificate } from './member.js';
const NOW = setMilliseconds(new Date(), 0);
const START_DATE = subMinutes(NOW, 5);
const EXPIRY_DATE = addMinutes(NOW, 5);
const { orgCertificate } = await generateMemberIdFixture();
describe('issueMemberCertificate', () => {
    describe('Member name', () => {
        test('should be the at sign if member is a bot', async () => {
            const certificate = await issueMemberCertificate(undefined, MEMBER_KEY_PAIR.publicKey, orgCertificate, ORG_KEY_PAIR.privateKey, EXPIRY_DATE);
            expect(certificate.commonName).toBe('@');
        });
        test('should be the specified name if set', async () => {
            const certificate = await issueMemberCertificate(MEMBER_NAME, MEMBER_KEY_PAIR.publicKey, orgCertificate, ORG_KEY_PAIR.privateKey, EXPIRY_DATE);
            expect(certificate.commonName).toBe(MEMBER_NAME);
        });
        test('should be well-formed', async () => {
            await expect(async () => issueMemberCertificate(`\n${MEMBER_NAME}`, MEMBER_KEY_PAIR.publicKey, orgCertificate, ORG_KEY_PAIR.privateKey, EXPIRY_DATE)).rejects.toThrow(VeraidError);
        });
    });
    test('Member public key should be honoured', async () => {
        const certificate = await issueMemberCertificate(MEMBER_NAME, MEMBER_KEY_PAIR.publicKey, orgCertificate, ORG_KEY_PAIR.privateKey, EXPIRY_DATE);
        await expect(derSerializePublicKey(await certificate.getPublicKey())).resolves.toStrictEqual(await derSerializePublicKey(MEMBER_KEY_PAIR.publicKey));
    });
    test('Certificate should be issued by organisation', async () => {
        const memberCertificate = await issueMemberCertificate(MEMBER_NAME, MEMBER_KEY_PAIR.publicKey, orgCertificate, ORG_KEY_PAIR.privateKey, EXPIRY_DATE);
        await expect(memberCertificate.getCertificationPath([], [orgCertificate])).resolves.toHaveLength(2);
    });
    test('Expiry date should match specified one', async () => {
        const certificate = await issueMemberCertificate(MEMBER_NAME, MEMBER_KEY_PAIR.publicKey, orgCertificate, ORG_KEY_PAIR.privateKey, EXPIRY_DATE);
        expect(certificate.validityPeriod.end).toStrictEqual(EXPIRY_DATE);
    });
    describe('Start date', () => {
        test('should default to now', async () => {
            const preIssuanceDate = new Date();
            const certificate = await issueMemberCertificate(MEMBER_NAME, MEMBER_KEY_PAIR.publicKey, orgCertificate, ORG_KEY_PAIR.privateKey, EXPIRY_DATE);
            expect(certificate.validityPeriod.start).toBeBetween(setMilliseconds(preIssuanceDate, 0), new Date());
        });
        test('should match explicit date if set', async () => {
            const certificate = await issueMemberCertificate(MEMBER_NAME, MEMBER_KEY_PAIR.publicKey, orgCertificate, ORG_KEY_PAIR.privateKey, EXPIRY_DATE, { startDate: START_DATE });
            expect(certificate.validityPeriod.start).toStrictEqual(START_DATE);
        });
    });
    describe('Basic constraints extension', () => {
        test('Subject should not be a CA', async () => {
            const certificate = await issueMemberCertificate(MEMBER_NAME, MEMBER_KEY_PAIR.publicKey, orgCertificate, ORG_KEY_PAIR.privateKey, EXPIRY_DATE);
            const basicConstraints = getBasicConstraintsExtension(certificate.pkijsCertificate);
            expect(basicConstraints.cA).toBeFalse();
        });
        test('Path length should be zero', async () => {
            const certificate = await issueMemberCertificate(MEMBER_NAME, MEMBER_KEY_PAIR.publicKey, orgCertificate, ORG_KEY_PAIR.privateKey, EXPIRY_DATE);
            const basicConstraints = getBasicConstraintsExtension(certificate.pkijsCertificate);
            expect(basicConstraints.pathLenConstraint).toBe(0);
        });
    });
});
//# sourceMappingURL=member.spec.js.map