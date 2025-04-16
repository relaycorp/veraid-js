/**
 * Return DER serialization of public key.
 */
export declare function derSerializePublicKey(publicKey: CryptoKey): Promise<Buffer>;
/**
 * Return DER serialization of private key.
 */
export declare function derSerializePrivateKey(privateKey: CryptoKey): Promise<Buffer>;
/**
 * Parse DER-serialized RSA public key.
 */
export declare function derDeserializeRsaPublicKey(publicKeyDer: ArrayBuffer | Buffer, algorithmOptions?: RsaHashedImportParams): Promise<CryptoKey>;
/**
 * Parse DER-serialized RSA private key.
 */
export declare function derDeserializeRsaPrivateKey(privateKeyDer: Buffer, algorithmOptions?: RsaHashedImportParams): Promise<CryptoKey>;
