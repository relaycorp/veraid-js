/**
 * Options for creating signatures
 */
export interface SignatureOptions {
    /**
     * Whether to include the plaintext in the signature bundle
     */
    shouldEncapsulatePlaintext: boolean;
    /**
     * The date from which the signature is valid
     */
    startDate: Date;
}
