import { AESKW } from '@stablelib/aes-kw';
import { AesKwProvider, type CryptoKey as WebCryptoKey } from 'webcrypto-core';

function typedArrayToBuffer(array: Uint8Array): ArrayBuffer {
  return array.buffer.slice(array.byteOffset, array.byteLength + array.byteOffset);
}

/**
 * AES-KW provider that uses pure JavaScript for encryption and decryption.
 */
export class AwalaAesKwProvider extends AesKwProvider {
  public constructor(protected readonly originalProvider: AesKwProvider) {
    super();
  }

  public async onGenerateKey(
    algorithm: AesKeyGenParams,
    isExtractable: boolean,
    keyUsages: KeyUsage[],
  ): Promise<WebCryptoKey> {
    return this.originalProvider.onGenerateKey(algorithm, isExtractable, keyUsages);
  }

  public async onExportKey(
    format: KeyFormat,
    key: WebCryptoKey,
  ): Promise<ArrayBuffer | JsonWebKey> {
    return this.originalProvider.onExportKey(format, key);
  }

  public async onImportKey(
    format: KeyFormat,
    keyData: ArrayBuffer | JsonWebKey,
    algorithm: Algorithm,
    isExtractable: boolean,
    keyUsages: KeyUsage[],
  ): Promise<WebCryptoKey> {
    return this.originalProvider.onImportKey(format, keyData, algorithm, isExtractable, keyUsages);
  }

  public override async onEncrypt(
    _algorithm: Algorithm,
    key: WebCryptoKey,
    data: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    const aesKw = await this.makeAesKw(key);
    return aesKw.wrapKey(new Uint8Array(data));
  }

  public override async onDecrypt(
    _algorithm: Algorithm,
    key: WebCryptoKey,
    data: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    const aesKw = await this.makeAesKw(key);
    return typedArrayToBuffer(aesKw.unwrapKey(new Uint8Array(data)));
  }

  private async makeAesKw(key: WebCryptoKey): Promise<AESKW> {
    const keyExported = (await this.onExportKey('raw', key)) as ArrayBuffer;
    return new AESKW(new Uint8Array(keyExported));
  }
}
