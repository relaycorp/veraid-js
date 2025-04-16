import { RsaPssProvider as BaseRsaPssProvider, type CryptoKey } from 'webcrypto-core';
export declare class RsaPssProvider extends BaseRsaPssProvider {
    protected readonly originalProvider: BaseRsaPssProvider;
    constructor(originalProvider: BaseRsaPssProvider);
    onVerify(_algorithm: RsaPssParams, key: CryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean>;
    onSign(algorithm: RsaPssParams, key: CryptoKey, data: ArrayBuffer, ...args: any[]): Promise<ArrayBuffer>;
    onGenerateKey(algorithm: RsaHashedKeyGenParams, isExtractable: boolean, keyUsages: KeyUsage[], ...args: any[]): Promise<CryptoKeyPair>;
    onExportKey(format: KeyFormat, key: CryptoKey, ...args: any[]): Promise<ArrayBuffer | JsonWebKey>;
    onImportKey(format: KeyFormat, keyData: ArrayBuffer | JsonWebKey, algorithm: RsaHashedImportParams, isExtractable: boolean, keyUsages: KeyUsage[], ...args: any[]): Promise<CryptoKey>;
}
