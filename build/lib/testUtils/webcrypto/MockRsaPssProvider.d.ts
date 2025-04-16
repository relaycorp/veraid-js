import { RsaPssProvider, type CryptoKey as WebCryptoKey } from 'webcrypto-core';
export declare class MockRsaPssProvider extends RsaPssProvider {
    readonly onGenerateKey: import("jest-mock").Mock<() => Promise<CryptoKeyPair>>;
    readonly onSign: import("jest-mock").Mock<() => Promise<ArrayBuffer>>;
    readonly onVerify: import("jest-mock").Mock<() => Promise<boolean>>;
    readonly onExportKey: import("jest-mock").Mock<() => Promise<ArrayBuffer | JsonWebKey>>;
    readonly onImportKey: import("jest-mock").Mock<() => Promise<WebCryptoKey>>;
}
