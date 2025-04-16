import { type MockChainFixture } from '@relaycorp/dnssec';
import { DatePeriod } from '../../lib/dates.js';
import type { Certificate } from '../../lib/utils/x509/Certificate.js';
interface MemberIdFixtureOptions {
    readonly orgCertificate: Certificate;
    readonly datePeriod: DatePeriod;
}
interface MemberIdFixture {
    readonly dnssecChainFixture: MockChainFixture;
    readonly orgCertificate: Certificate;
    readonly memberCertificate: Certificate;
    readonly datePeriod: DatePeriod;
}
export declare function generateMemberIdFixture(options?: Partial<MemberIdFixtureOptions>): Promise<MemberIdFixture>;
export {};
