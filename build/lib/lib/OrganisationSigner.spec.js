import { generateMemberIdFixture } from '../testUtils/veraStubs/memberIdFixture.js';
import { serialiseMessage } from '../testUtils/dns.js';
import { MEMBER_NAME } from '../testUtils/veraStubs/member.js';
import { bufferToArray } from './utils/buffers.js';
import { VeraidDnssecChain } from './dns/VeraidDnssecChain.js';
import { OrganisationSigner } from './OrganisationSigner.js';
const { orgCertificate, dnssecChainFixture } = await generateMemberIdFixture();
const dnssecChain = new VeraidDnssecChain(orgCertificate.commonName, dnssecChainFixture.responses.map(serialiseMessage).map(bufferToArray));
describe('OrganisationSigner', () => {
    describe('signerCertificate', () => {
        test('should return undefined', () => {
            const signer = new OrganisationSigner(dnssecChain, orgCertificate);
            const { signerCertificate } = signer;
            expect(signerCertificate).toBeUndefined();
        });
    });
    describe('signerName', () => {
        test('should return undefined if attributedMemberName is not provided', () => {
            const signer = new OrganisationSigner(dnssecChain, orgCertificate);
            const { signerName } = signer;
            expect(signerName).toBeUndefined();
        });
        test('should return attributedMemberName if provided', () => {
            const signer = new OrganisationSigner(dnssecChain, orgCertificate, MEMBER_NAME);
            const { signerName } = signer;
            expect(signerName).toBe(MEMBER_NAME);
        });
    });
});
//# sourceMappingURL=OrganisationSigner.spec.js.map