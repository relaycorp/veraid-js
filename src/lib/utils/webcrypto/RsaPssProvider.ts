import { RSA_PKCS1_PSS_PADDING } from 'node:constants';
import { createVerify, type VerifyPublicKeyInput } from 'node:crypto';

import { RsaPssProvider as BaseRsaPssProvider, type CryptoKey } from 'webcrypto-core';

/**
 * Custom RSA-PSS provider that lets Node.js determine the salt length.
 *
 * This is a workaround for: https://github.com/relaycorp/webcrypto-kms-js/issues/242
 */
export class RsaPssProvider extends BaseRsaPssProvider {
  public constructor(protected readonly originalProvider: BaseRsaPssProvider) {
    super();
  }

  public override async onVerify(
    _algorithm: RsaPssParams,
    key: CryptoKey,
    signature: ArrayBuffer,
    data: ArrayBuffer,
  ) {
    const signer = createVerify((key.algorithm as RsaHashedKeyAlgorithm).hash.name);
    signer.update(new Uint8Array(data));

    const keyPem = await this.exportPublicKeyToPem(key);
    const options: VerifyPublicKeyInput = {
      key: keyPem,
      padding: RSA_PKCS1_PSS_PADDING,
    };

    return signer.verify(options, new Uint8Array(signature));
  }

  private async exportPublicKeyToPem(key: CryptoKey) {
    const keyDer = (await this.exportKey('spki', key)) as ArrayBuffer;
    const keyBase64 = Buffer.from(keyDer).toString('base64');
    return `-----BEGIN PUBLIC KEY-----\n${keyBase64}\n-----END PUBLIC KEY-----`;
  }

  public override async onSign(
    algorithm: RsaPssParams,
    key: CryptoKey,
    data: ArrayBuffer,
    ...args: any[]
  ) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
    return this.originalProvider.onSign(algorithm, key, data, ...args);
  }

  public override async onGenerateKey(
    algorithm: RsaHashedKeyGenParams,
    isExtractable: boolean,
    keyUsages: KeyUsage[],
    ...args: any[]
  ) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
    return this.originalProvider.onGenerateKey(algorithm, isExtractable, keyUsages, ...args);
  }

  public override async onExportKey(format: KeyFormat, key: CryptoKey, ...args: any[]) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
    return this.originalProvider.onExportKey(format, key, ...args);
  }

  public override async onImportKey(
    format: KeyFormat,
    keyData: ArrayBuffer | JsonWebKey,
    algorithm: RsaHashedImportParams,
    isExtractable: boolean,
    keyUsages: KeyUsage[],
    ...args: any[]
  ) {
    return this.originalProvider.onImportKey(
      format,
      keyData,
      algorithm,
      isExtractable,
      keyUsages,
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
      ...args,
    );
  }
}
