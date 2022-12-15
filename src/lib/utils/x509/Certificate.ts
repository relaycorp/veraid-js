import { BmpString, Integer, OctetString, type BaseBlock } from 'asn1js';
import { min, setMilliseconds } from 'date-fns';
import {
  AttributeTypeAndValue,
  AuthorityKeyIdentifier,
  BasicConstraints,
  Certificate as PkijsCertificate,
  CertificateChainValidationEngine,
  Extension,
  type FindIssuerCallback,
} from 'pkijs';

import { getIdFromIdentityKey, getPublicKeyDigest } from '../keys.js';
import { getEngineForPrivateKey } from '../webcrypto/engine.js';
import { AUTHORITY_KEY, BASIC_CONSTRAINTS, COMMON_NAME, SUBJECT_KEY } from '../../oids.js';
import { derDeserialize } from '../asn1.js';
import { generateRandom64BitValue } from '../crypto.js';

import CertificateError from './CertificateError.js';
import type FullCertificateIssuanceOptions from './FullCertificateIssuanceOptions.js';

const X509_CERTIFICATE_VERSION_3 = 2;

const SIGNED_INTEGER_MAX_OCTET = 127;

type FindIssuerSignature = (
  cert: PkijsCertificate,
  engine: CertificateChainValidationEngine,
) => Promise<readonly PkijsCertificate[]>;

function generatePositiveAsn1Integer(): Integer {
  const potentiallySignedInteger = new Uint8Array(generateRandom64BitValue());

  // ASN.1 BER/DER INTEGER uses two's complement with big endian, so we ensure the integer is
  // positive by keeping the leftmost octet below 128.
  const positiveInteger = new Uint8Array(potentiallySignedInteger);
  positiveInteger.set([Math.min(potentiallySignedInteger[0], SIGNED_INTEGER_MAX_OCTET)], 0);

  return new Integer({ valueHex: positiveInteger });
}

function makeBasicConstraintsExtension(isCa: boolean, pathLengthConstraint: number): Extension {
  if (pathLengthConstraint < 0) {
    throw new CertificateError(`pathLenConstraint must be >= 0 (got ${pathLengthConstraint})`);
  }
  const basicConstraints = new BasicConstraints({
    cA: isCa,
    pathLenConstraint: pathLengthConstraint,
  });
  return new Extension({
    critical: true,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    extnID: BASIC_CONSTRAINTS,
    extnValue: basicConstraints.toSchema().toBER(false),
  });
}

async function makeAuthorityKeyIdExtension(publicKey: CryptoKey): Promise<Extension> {
  const keyDigest = await getPublicKeyDigest(publicKey);
  const keyIdEncoded = new OctetString({ valueHex: keyDigest });
  return new Extension({
    // eslint-disable-next-line @typescript-eslint/naming-convention
    extnID: AUTHORITY_KEY,
    extnValue: new AuthorityKeyIdentifier({ keyIdentifier: keyIdEncoded }).toSchema().toBER(false),
  });
}

async function makeSubjectKeyIdExtension(publicKey: CryptoKey): Promise<Extension> {
  const keyDigest = await getPublicKeyDigest(publicKey);
  return new Extension({
    // eslint-disable-next-line @typescript-eslint/naming-convention
    extnID: SUBJECT_KEY,
    extnValue: new OctetString({ valueHex: keyDigest }).toBER(false),
  });
}

function cloneAsn1jsValue<Type extends BaseBlock>(value: Type): Type {
  const valueSerialized = value.toBER(false);
  return derDeserialize(valueSerialized) as Type;
}

/**
 * X.509 Certificate.
 *
 * This is a high-level class on top of PKI.js Certificate, to make the use of Relaynet
 * certificates easy and safe.
 */
export default class Certificate {
  protected static validateIssuerCertificate(issuerCertificate: Certificate): void {
    const extensions = issuerCertificate.pkijsCertificate.extensions ?? [];
    const bcExtension = extensions.find((extension) => extension.extnID === BASIC_CONSTRAINTS);
    if (bcExtension === undefined) {
      throw new CertificateError('Basic constraints extension is missing from issuer certificate');
    }
    const basicConstraintsAsn1 = derDeserialize(bcExtension.extnValue.valueBlock.valueHex);
    const basicConstraints = new BasicConstraints({ schema: basicConstraintsAsn1 });
    if (!basicConstraints.cA) {
      throw new CertificateError('Issuer is not a CA');
    }
  }

  protected static isCertificateInArray(
    certificate: Certificate,
    array: readonly Certificate[],
  ): boolean {
    for (const certInArray of array) {
      if (certInArray.isEqual(certificate)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Deserialize certificate from DER-encoded value.
   *
   * @param certDer DER-encoded X.509 certificate
   */
  public static deserialize(certDer: ArrayBuffer): Certificate {
    const asn1Value = derDeserialize(certDer);
    const pkijsCert = new PkijsCertificate({ schema: asn1Value });
    return new Certificate(pkijsCert);
  }

  /**
   * Issue a Relaynet PKI certificate.
   */
  public static async issue(options: FullCertificateIssuanceOptions): Promise<Certificate> {
    // PKI.js should round down to the nearest second per X.509. We should do it ourselves to
    // avoid discrepancies when the validity dates of a freshly-issued certificate are used.
    const validityStartDate = setMilliseconds(options.validityStartDate ?? new Date(), 0);
    const validityEndDate = setMilliseconds(
      options.issuerCertificate
        ? min([options.issuerCertificate.expiryDate, options.validityEndDate])
        : options.validityEndDate,
      0,
    );

    // region Validation
    if (validityEndDate < validityStartDate) {
      throw new CertificateError('The end date must be later than the start date');
    }
    if (options.issuerCertificate) {
      Certificate.validateIssuerCertificate(options.issuerCertificate);
    }

    // endregion

    const issuerPublicKey = options.issuerCertificate
      ? await options.issuerCertificate.pkijsCertificate.getPublicKey()
      : options.subjectPublicKey;
    const pkijsCert = new PkijsCertificate({
      extensions: [
        makeBasicConstraintsExtension(Boolean(options.isCa), options.pathLenConstraint ?? 0),
        await makeAuthorityKeyIdExtension(issuerPublicKey),
        await makeSubjectKeyIdExtension(options.subjectPublicKey),
      ],

      serialNumber: generatePositiveAsn1Integer(),
      version: X509_CERTIFICATE_VERSION_3,
    });

    pkijsCert.notBefore.value = validityStartDate;

    pkijsCert.notAfter.value = validityEndDate;

    pkijsCert.subject.typesAndValues.push(
      new AttributeTypeAndValue({
        type: COMMON_NAME,
        value: new BmpString({ value: options.commonName }),
      }),
    );

    const issuerDn = options.issuerCertificate
      ? options.issuerCertificate.pkijsCertificate.subject.typesAndValues
      : pkijsCert.subject.typesAndValues;
    pkijsCert.issuer.typesAndValues = issuerDn.map(
      (attribute) =>
        new AttributeTypeAndValue({
          type: attribute.type,
          value: cloneAsn1jsValue(attribute.value),
        }),
    );

    await pkijsCert.subjectPublicKeyInfo.importKey(options.subjectPublicKey);

    const signatureHashAlgo = (options.issuerPrivateKey.algorithm as RsaHashedKeyGenParams)
      .hash as Algorithm;
    const engine = getEngineForPrivateKey(options.issuerPrivateKey);
    await pkijsCert.sign(options.issuerPrivateKey, signatureHashAlgo.name, engine);
    return new Certificate(pkijsCert);
  }

  protected subjectIdCache: string | null = null;

  public constructor(public readonly pkijsCertificate: PkijsCertificate) {
    this.pkijsCertificate = pkijsCertificate;
  }

  public get startDate(): Date {
    return this.pkijsCertificate.notBefore.value;
  }

  public get expiryDate(): Date {
    return this.pkijsCertificate.notAfter.value;
  }

  /**
   * Serialize certificate as DER-encoded buffer.
   */
  public serialize(): ArrayBuffer {
    const certAsn1js = this.pkijsCertificate.toSchema(true);
    return certAsn1js.toBER(false);
  }

  /**
   * Return serial number.
   *
   * This doesn't return a `number` or `BigInt` because the serial number could require more than
   * 8 octets (which is the maximum number of octets required to represent a 64-bit unsigned
   * integer).
   */
  public getSerialNumber(): Buffer {
    const serialNumberBlock = this.pkijsCertificate.serialNumber;
    const serialNumber = serialNumberBlock.valueBlock.toBER();
    return Buffer.from(serialNumber);
  }

  public getSerialNumberHex(): string {
    const serialNumber = this.getSerialNumber();
    return serialNumber.toString('hex');
  }

  public getCommonName(): string {
    const commonNameAttribute = this.pkijsCertificate.subject.typesAndValues.find(
      (attribute) => (attribute.type as unknown as string) === COMMON_NAME,
    );
    if (commonNameAttribute === undefined) {
      throw new CertificateError('Distinguished Name does not contain Common Name');
    }
    return commonNameAttribute.value.valueBlock.value;
  }

  /**
   * Report whether this certificate is the same as `otherCertificate`.
   */
  public isEqual(otherCertificate: Certificate): boolean {
    const thisCertSerialized = Buffer.from(this.serialize());
    const otherCertSerialized = Buffer.from(otherCertificate.serialize());
    return thisCertSerialized.equals(otherCertSerialized);
  }

  public validate(): void {
    // X.509 versioning starts at 0
    const x509CertVersion = this.pkijsCertificate.version;
    if (x509CertVersion !== X509_CERTIFICATE_VERSION_3) {
      throw new CertificateError(
        `Only X.509 v3 certificates are supported (got v${x509CertVersion + 1})`,
      );
    }

    const currentDate = new Date();
    if (currentDate < this.startDate) {
      throw new CertificateError('Certificate is not yet valid');
    }
    if (this.expiryDate < currentDate) {
      throw new CertificateError('Certificate already expired');
    }
  }

  public getIssuerId(): string | null {
    const authorityKeyAttribute = this.pkijsCertificate.extensions?.find(
      (attribute) => attribute.extnID === AUTHORITY_KEY,
    );
    if (!authorityKeyAttribute) {
      return null;
    }
    const authorityKeyId = authorityKeyAttribute.parsedValue as AuthorityKeyIdentifier;
    if (!authorityKeyId.keyIdentifier) {
      throw new CertificateError('Key identifier is missing from AKI extension');
    }
    const id = Buffer.from(authorityKeyId.keyIdentifier.valueBlock.valueHexView).toString('hex');
    return `0${id}`;
  }

  public async getPublicKey(): Promise<CryptoKey> {
    return this.pkijsCertificate.getPublicKey();
  }

  public async calculateSubjectId(): Promise<string> {
    if (this.subjectIdCache === null) {
      this.subjectIdCache = await getIdFromIdentityKey(await this.getPublicKey());
    }
    return this.subjectIdCache;
  }

  /**
   * Return the certification path (aka "certificate chain") if this certificate can be trusted.
   *
   * @param intermediateCaCertificates The alleged chain for the certificate
   * @param trustedCertificates The collection of certificates that are actually trusted
   * @throws CertificateError when this certificate is not on a certificate path from a CA in
   *   `trustedCertificates`
   */
  public async getCertificationPath(
    intermediateCaCertificates: readonly Certificate[],
    trustedCertificates: readonly Certificate[],
  ): Promise<readonly Certificate[]> {
    async function findIssuer(
      pkijsCertificate: PkijsCertificate,
      validationEngine: { readonly defaultFindIssuer: FindIssuerSignature },
    ): Promise<readonly PkijsCertificate[]> {
      const issuers = await validationEngine.defaultFindIssuer(
        pkijsCertificate,
        validationEngine as CertificateChainValidationEngine,
      );
      if (issuers.length !== 0) {
        return issuers;
      }

      // If the certificate is actually an intermediate certificate, but it's passed as a trusted
      // certificate, accepted it.
      const certificate = new Certificate(pkijsCertificate);
      return Certificate.isCertificateInArray(certificate, trustedCertificates)
        ? [pkijsCertificate]
        : [];
    }

    // Ignore any intermediate certificate that's also the issuer of a trusted certificate.
    // The main reason for doing this isn't performance, but the fact that PKI.js would fail to
    // compute the path.
    const intermediateCertsSanitized = intermediateCaCertificates.filter((certificate) => {
      for (const trustedCertificate of trustedCertificates) {
        if (
          trustedCertificate.pkijsCertificate.issuer.isEqual(certificate.pkijsCertificate.subject)
        ) {
          return false;
        }
      }
      return true;
    });

    const chainValidator = new CertificateChainValidationEngine({
      certs: [
        ...intermediateCertsSanitized.map((certificate) => certificate.pkijsCertificate),
        this.pkijsCertificate,
      ],

      findIssuer: findIssuer as unknown as FindIssuerCallback,
      trustedCerts: trustedCertificates.map((certificate) => certificate.pkijsCertificate),
    });
    const verification = await chainValidator.verify({ passedWhenNotRevValues: false });

    if (!verification.result) {
      throw new CertificateError(verification.resultMessage);
    }

    return verification.certificatePath!.map(
      (pkijsCert: PkijsCertificate) => new Certificate(pkijsCert),
    );
  }
}
