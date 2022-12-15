import { ObjectIdentifier, OctetString } from 'asn1js';
import {
  Attribute,
  type Certificate as PkijsCertificate,
  ContentInfo,
  EncapsulatedContentInfo,
  IssuerAndSerialNumber,
  SignedAndUnsignedAttributes,
  SignedData as PkijsSignedData,
  type SignedDataVerifyResult,
  SignerInfo,
} from 'pkijs';

import { getPkijsCrypto } from '../pkijs.js';
import { getEngineForPrivateKey } from '../webcrypto/engine.js';
import Certificate from '../x509/Certificate.js';
import { CMS_OIDS } from '../../oids.js';

import { deserializeContentInfo } from './utils.js';
import CmsError from './CmsError.js';
import { type SignatureOptions } from './SignatureOptions.js';

const pkijsCrypto = getPkijsCrypto();

interface SignedDataOptions extends SignatureOptions {
  readonly encapsulatePlaintext: boolean;
}

function initSignerInfo(signerCertificate: Certificate, digest: ArrayBuffer): SignerInfo {
  const signerIdentifier = new IssuerAndSerialNumber({
    issuer: signerCertificate.pkijsCertificate.issuer,
    serialNumber: signerCertificate.pkijsCertificate.serialNumber,
  });
  const contentTypeAttribute = new Attribute({
    type: CMS_OIDS.ATTR_CONTENT_TYPE,
    values: [new ObjectIdentifier({ value: CMS_OIDS.DATA })],
  });
  const digestAttribute = new Attribute({
    type: CMS_OIDS.ATTR_DIGEST,
    values: [new OctetString({ valueHex: digest })],
  });
  return new SignerInfo({
    sid: signerIdentifier,

    signedAttrs: new SignedAndUnsignedAttributes({
      attributes: [contentTypeAttribute, digestAttribute],
      type: 0,
    }),

    version: 1,
  });
}

export class SignedData {
  private static reDeserialize(pkijsSignedData: PkijsSignedData): SignedData {
    const signedData = new SignedData(pkijsSignedData);
    const serialization = signedData.serialize();
    return SignedData.deserialize(serialization);
  }

  public static deserialize(signedDataSerialized: ArrayBuffer): SignedData {
    const contentInfo = deserializeContentInfo(signedDataSerialized);
    let pkijsSignedData: PkijsSignedData;
    try {
      pkijsSignedData = new PkijsSignedData({ schema: contentInfo.content });
    } catch (error) {
      throw new CmsError('SignedData value is malformed', { cause: error });
    }
    return new SignedData(pkijsSignedData);
  }

  public static async sign(
    plaintext: ArrayBuffer,
    privateKey: CryptoKey,
    signerCertificate: Certificate,
    caCertificates: readonly Certificate[] = [],
    options: Partial<SignedDataOptions> = {},
  ): Promise<SignedData> {
    // RS-018 prohibits the use of MD5 and SHA-1, but WebCrypto doesn't support MD5
    if ((options.hashingAlgorithmName as any) === 'SHA-1') {
      throw new CmsError('SHA-1 is disallowed by RS-018');
    }

    const hashingAlgorithmName = options.hashingAlgorithmName ?? 'SHA-256';
    const digest = await pkijsCrypto.digest({ name: hashingAlgorithmName }, plaintext);
    const signerInfo = initSignerInfo(signerCertificate, digest);
    const shouldEncapsulatePlaintext = options.encapsulatePlaintext ?? true;
    const pkijsSignedData = new PkijsSignedData({
      certificates: [signerCertificate, ...caCertificates].map((cert) => cert.pkijsCertificate),

      encapContentInfo: new EncapsulatedContentInfo({
        eContentType: CMS_OIDS.DATA,
        ...(shouldEncapsulatePlaintext && { eContent: new OctetString({ valueHex: plaintext }) }),
      }),

      signerInfos: [signerInfo],
      version: 1,
    });
    await pkijsSignedData.sign(
      privateKey,
      0,
      hashingAlgorithmName,
      shouldEncapsulatePlaintext ? undefined : plaintext,
      getEngineForPrivateKey(privateKey),
    );

    return SignedData.reDeserialize(pkijsSignedData);
  }

  public constructor(public readonly pkijsSignedData: PkijsSignedData) {}

  /**
   * The signed plaintext, if it was encapsulated.
   */
  public get plaintext(): ArrayBuffer | null {
    const content = this.pkijsSignedData.encapContentInfo.eContent;
    return content?.getValue() ?? null;
  }

  /**
   * The signer's certificate, if it was encapsulated.
   */
  public get signerCertificate(): Certificate | null {
    if (this.pkijsSignedData.signerInfos.length === 0) {
      return null;
    }
    const [signerInfo] = this.pkijsSignedData.signerInfos;
    const match = Array.from(this.certificates).find((cert) => {
      const sid = signerInfo.sid as IssuerAndSerialNumber;
      return (
        cert.pkijsCertificate.issuer.isEqual(sid.issuer) &&
        cert.pkijsCertificate.serialNumber.isEqual(sid.serialNumber)
      );
    });
    return match ?? null;
  }

  /**
   * Set of encapsulated certificates.
   */
  public get certificates(): Set<Certificate> {
    const certificates = (this.pkijsSignedData.certificates as readonly PkijsCertificate[]).map(
      (cert) => new Certificate(cert),
    );
    return new Set(certificates);
  }

  public serialize(): ArrayBuffer {
    const contentInfo = new ContentInfo({
      content: this.pkijsSignedData.toSchema(true),
      contentType: CMS_OIDS.SIGNED_DATA,
    });
    return contentInfo.toSchema().toBER(false);
  }

  public async verify(expectedPlaintext?: ArrayBuffer): Promise<void> {
    const currentPlaintext = this.plaintext;
    const isPlaintextEncapsulated = currentPlaintext !== null;
    if (isPlaintextEncapsulated && expectedPlaintext !== undefined) {
      throw new CmsError(
        'No specific plaintext should be expected because one is already encapsulated',
      );
    }
    if (!isPlaintextEncapsulated && expectedPlaintext === undefined) {
      throw new CmsError('Plaintext should be encapsulated or explicitly set');
    }

    let verificationResult: SignedDataVerifyResult;
    try {
      verificationResult = await this.pkijsSignedData.verify({
        data: isPlaintextEncapsulated ? undefined : expectedPlaintext,
        extendedMode: true,
        signer: 0,
      });
    } catch (err) {
      throw new CmsError('Invalid signature', { cause: err });
    }

    if (verificationResult.signatureVerified !== true) {
      throw new CmsError(`Invalid signature (PKI.js code: ${verificationResult.code!})`);
    }
  }
}
