import { DnsClass, DnsRecord, MockChain, RrSet, SecurityStatus, } from '@relaycorp/dnssec';
import { differenceInSeconds, setMilliseconds } from 'date-fns';
import { SignatureBundle } from '../SignatureBundle.js';
import { MemberIdBundle } from '../memberIdBundle/MemberIdBundle.js';
import { OrganisationSigner } from '../OrganisationSigner.js';
import { VeraidDnssecChain } from '../dns/VeraidDnssecChain.js';
import { selfIssueOrganisationCertificate } from '../pki/organisation.js';
import { issueMemberCertificate } from '../pki/member.js';
import { generateRsaKeyPair } from '../utils/keys/generation.js';
import { DatePeriod } from '../dates.js';
import { bufferToArray } from '../utils/buffers.js';
import { generateTxtRdata } from '../dns/rdataSerialisation.js';
async function generateVeraidRrSet(domain, datePeriod, orgKeyPair) {
    const veraidDomain = `_veraid.${domain}`;
    const ttlOverride = differenceInSeconds(datePeriod.end, datePeriod.start);
    const txtRdata = await generateTxtRdata(orgKeyPair.publicKey, ttlOverride);
    const veraidRecord = new DnsRecord(veraidDomain, 'TXT', DnsClass.IN, ttlOverride, txtRdata);
    return RrSet.init(veraidRecord.makeQuestion(), [veraidRecord]);
}
async function generateDnssecChain(zone, orgKeyPair, datePeriod) {
    const mockDnssecChain = await MockChain.generate(zone);
    const veraidRrSet = await generateVeraidRrSet(zone, datePeriod, orgKeyPair);
    const { responses, trustAnchors } = mockDnssecChain.generateFixture(veraidRrSet, SecurityStatus.SECURE, datePeriod);
    const responsesArrayBuffers = responses.map((response) => bufferToArray(response.serialise()));
    const veraidDnssecChain = new VeraidDnssecChain(zone, responsesArrayBuffers);
    return { veraidDnssecChain, trustAnchors };
}
async function createChain(zone, shouldBeSignedByMember, userName, orgKeyPair, veraidDnssecChain, validityPeriod) {
    const orgCertificate = await selfIssueOrganisationCertificate(zone, orgKeyPair, validityPeriod.end, { startDate: validityPeriod.start });
    if (!shouldBeSignedByMember) {
        return {
            chain: new OrganisationSigner(veraidDnssecChain, orgCertificate, userName),
            signerPrivateKey: orgKeyPair.privateKey,
        };
    }
    const memberKeyPair = await generateRsaKeyPair();
    const memberCert = await issueMemberCertificate(userName, memberKeyPair.publicKey, orgCertificate, orgKeyPair.privateKey, validityPeriod.end, { startDate: validityPeriod.start });
    return {
        chain: new MemberIdBundle(veraidDnssecChain, orgCertificate, memberCert),
        signerPrivateKey: memberKeyPair.privateKey,
    };
}
/**
 * Mock trust chain for testing purposes
 */
export class MockTrustChain {
    /**
     * Generate a mock trust chain
     * @param orgName - The name of the organisation
     * @param userName - The name of the user
     * @param expiryDate - The expiry date of the trust chain
     * @param options - The options for the mock trust chain
     * @returns A mock trust chain
     */
    static async generate(orgName, userName, expiryDate, options = {}) {
        const startDate = options.startDate ?? setMilliseconds(new Date(), 0);
        const zone = `${orgName}.`;
        const datePeriod = DatePeriod.init(startDate, expiryDate);
        const orgKeyPair = await generateRsaKeyPair();
        const { veraidDnssecChain, trustAnchors } = await generateDnssecChain(zone, orgKeyPair, datePeriod);
        const { chain, signerPrivateKey } = await createChain(zone, options.shouldBeSignedByMember ?? true, userName, orgKeyPair, veraidDnssecChain, datePeriod);
        return new MockTrustChain(trustAnchors, chain, signerPrivateKey, datePeriod);
    }
    constructor(dnssecTrustAnchors, chain, signerPrivateKey, validityPeriod) {
        this.dnssecTrustAnchors = dnssecTrustAnchors;
        this.chain = chain;
        this.signerPrivateKey = signerPrivateKey;
        this.validityPeriod = validityPeriod;
    }
    /**
     * Sign a plaintext with the chain
     * @param plaintext - The plaintext to sign
     * @param serviceOid - The service OID for which to sign the plaintext
     * @param shouldEncapsulatePlaintext - Whether to encapsulate the plaintext in the signature
     * @returns A signature bundle
     */
    async sign(plaintext, serviceOid, shouldEncapsulatePlaintext = true) {
        return SignatureBundle.sign(plaintext, serviceOid, this.chain, this.signerPrivateKey, this.validityPeriod.end, {
            shouldEncapsulatePlaintext,
            startDate: this.validityPeriod.start,
        });
    }
}
//# sourceMappingURL=MockTrustChain.js.map