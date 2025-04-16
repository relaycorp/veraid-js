/**
 * Options to generate mock trust chains.
 */
export interface MockTrustChainOptions {
    readonly startDate: Date;
    readonly shouldBeSignedByMember: boolean;
}
