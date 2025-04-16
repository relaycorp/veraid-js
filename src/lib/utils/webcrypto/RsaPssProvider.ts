import { RSA_PKCS1_PSS_PADDING } from 'node:constants';
import { createVerify } from 'node:crypto';

import { RsaPssProvider as BaseRsaPssProvider, type CryptoKey } from 'webcrypto-core';

function getCryptoAlgorithm(alg: RsaHashedKeyAlgorithm): string {
  switch (alg.hash.name.toUpperCase()) {
    case 'SHA-256': {
      return 'RSA-SHA256';
    }
    case 'SHA-384': {
      return 'RSA-SHA384';
    }
    case 'SHA-512': {
      return 'RSA-SHA512';
    }
    default: {
      throw new Error(`Unrecognised or unsupported hash algorithm (${alg.hash.name})`);
    }
  }
}

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
    const cryptoAlg = getCryptoAlgorithm(key.algorithm as RsaHashedKeyAlgorithm);
    const signer = createVerify(cryptoAlg);
    signer.update(Buffer.from(data));

    const keyDer = (await this.exportKey('spki', key)) as ArrayBuffer;
    const keyPem = Buffer.from(keyDer).toString('base64');
    const options = {
      key: `-----BEGIN PUBLIC KEY-----\n${keyPem}\n-----END PUBLIC KEY-----`,
      padding: RSA_PKCS1_PSS_PADDING,
    };

    return signer.verify(options, new Uint8Array(signature));
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
