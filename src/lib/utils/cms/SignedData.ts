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

import { NODE_ENGINE } from '../pkijs.js';
import { getEngineForPrivateKey } from '../webcrypto/engine.js';
import Certificate from '../x509/Certificate.js';
import { CMS_OIDS } from '../../oids.js';

import { deserializeContentInfo } from './utils.js';
import CmsError from './CmsError.js';
import type { SignedDataSignatureOptions } from './SignedDataSignatureOptions.js';

function initSignerInfo(
  signerCertificate: Certificate,
  digest: ArrayBuffer,
  extraAttributes: readonly Attribute[],
): SignerInfo {
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
      attributes: [contentTypeAttribute, digestAttribute, ...extraAttributes],
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

  /**
   * Create a CMS SignedData value for the specified plaintext.
   * @param plaintext - The plaintext to be signed
   * @param privateKey - The private key to sign with
   * @param signerCertificate - The certificate corresponding to the private key
   * @param attachedCertificates - The certificates to attach to the SignedData (empty by default)
   *                               The signer certificate is NOT automatically attached.
   * @param options - Additional options for the signature
   * @returns The SignedData object
   * @throws {CmsError} If the hashing algorithm is unsupported
   */
  public static async sign(
    plaintext: ArrayBuffer,
    privateKey: CryptoKey,
    signerCertificate: Certificate,
    attachedCertificates: readonly Certificate[] = [],
    options: Partial<SignedDataSignatureOptions> = {},
  ): Promise<SignedData> {
    if ((options.hashingAlgorithmName as any) === 'SHA-1') {
      throw new CmsError('SHA-1 is unsupported');
    }

    const hashingAlgorithmName = options.hashingAlgorithmName ?? 'SHA-256';
    const digest = await NODE_ENGINE.digest({ name: hashingAlgorithmName }, plaintext);
    const signerInfo = initSignerInfo(signerCertificate, digest, options.extraSignedAttrs ?? []);
    const shouldEncapsulatePlaintext = options.shouldEncapsulatePlaintext ?? true;
    const pkijsSignedData = new PkijsSignedData({
      certificates: attachedCertificates.map((cert) => cert.pkijsCertificate),

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
    const sid = this.signerIssuerAndSerialNumber;
    if (!sid) {
      return null;
    }
    const match = Array.from(this.certificates).find((cert) =>
      cert.matchesIssuerAndSerialNumber(sid),
    );
    return match ?? null;
  }

  /**
   * The signer's issuer and serial number, if available.
   */
  public get signerIssuerAndSerialNumber(): IssuerAndSerialNumber | null {
    if (this.pkijsSignedData.signerInfos.length === 0) {
      return null;
    }
    const [signerInfo] = this.pkijsSignedData.signerInfos;
    return signerInfo.sid as IssuerAndSerialNumber;
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

  public getSignedAttribute(type: string): any[] | null {
    if (this.pkijsSignedData.signerInfos.length === 0) {
      throw new CmsError('SignedData value does not have any signers');
    }
    const [{ signedAttrs: signedAttributes }] = this.pkijsSignedData.signerInfos;
    const signedAttribute = signedAttributes?.attributes.find(
      (attribute) => attribute.type === type,
    );
    return signedAttribute?.values ?? null;
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
      verificationResult = await this.pkijsSignedData.verify(
        {
          data: isPlaintextEncapsulated ? undefined : expectedPlaintext,
          extendedMode: true,
          signer: 0,
        },
        NODE_ENGINE,
      );
    } catch (err) {
      throw new CmsError('Invalid signature', { cause: err });
    }

    if (verificationResult.signatureVerified !== true) {
      throw new CmsError(`Invalid signature (PKI.js code: ${verificationResult.code!})`);
    }
  }
}
