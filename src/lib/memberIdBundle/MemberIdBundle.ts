import type { Certificate as CertificateSchema } from '@peculiar/asn1-x509';
import { AsnParser, AsnSerializer } from '@peculiar/asn1-schema';

import type { DnssecChainSchema } from '../schemas/DnssecChainSchema.js';
import Certificate from '../utils/x509/Certificate.js';
import VeraidError from '../VeraidError.js';
import { MemberIdBundleSchema } from '../schemas/MemberIdBundleSchema.js';
import { BOT_NAME } from '../pki/member.js';
import { Chain } from '../Chain.js';

/**
 * VeraId member identity bundle containing certificates and DNSSEC chain
 */
export class MemberIdBundle extends Chain {
  /**
   * Deserialise a member ID bundle from its binary representation
   * @param memberIdBundleSerialised - The serialised member ID bundle
   * @returns A new MemberIdBundle instance
   * @throws If the bundle is malformed
   */
  public static deserialise(memberIdBundleSerialised: ArrayBuffer): MemberIdBundle {
    let memberIdBundleSchema: MemberIdBundleSchema;
    try {
      memberIdBundleSchema = AsnParser.parse(memberIdBundleSerialised, MemberIdBundleSchema);
    } catch {
      throw new VeraidError('Member id bundle is malformed');
    }

    return new MemberIdBundle(
      memberIdBundleSchema.dnssecChain,
      memberIdBundleSchema.organisationCertificate,
      memberIdBundleSchema.memberCertificate,
    );
  }

  /**
   * Create a MemberIdBundle instance from an ASN.1 schema
   * @param schema - The ASN.1 schema representation of a member ID bundle
   * @returns A new MemberIdBundle instance
   */
  public static fromSchema(schema: MemberIdBundleSchema): MemberIdBundle {
    return new MemberIdBundle(
      schema.dnssecChain,
      schema.organisationCertificate,
      schema.memberCertificate,
    );
  }

  public constructor(
    dnssecChainSchema: DnssecChainSchema,
    orgCertificateSchema: CertificateSchema,
    public readonly memberCertificateSchema: CertificateSchema,
  ) {
    super(dnssecChainSchema, orgCertificateSchema);
  }

  /**
   * Serialise this member ID bundle to its binary representation
   * @returns The serialised member ID bundle
   */
  public serialise(): ArrayBuffer {
    const schema = this.toSchema();
    return AsnSerializer.serialize(schema);
  }

  /**
   * Convert a MemberIdBundle instance to its ASN.1 schema representation
   * @returns The ASN.1 schema representation of the member ID bundle
   */
  public toSchema(): MemberIdBundleSchema {
    const bundle = new MemberIdBundleSchema();
    bundle.version = 0;
    bundle.memberCertificate = this.memberCertificateSchema;
    bundle.organisationCertificate = this.orgCertificateSchema;
    bundle.dnssecChain = this.dnssecChainSchema;
    return bundle;
  }

  public override get signerCertificateSchema(): CertificateSchema {
    return this.memberCertificateSchema;
  }

  public override get signerName(): string | undefined {
    const memberCertificate = Certificate.deserialize(
      AsnSerializer.serialize(this.memberCertificateSchema),
    );
    return memberCertificate.commonName === BOT_NAME ? undefined : memberCertificate.commonName;
  }
}
