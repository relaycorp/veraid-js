/* eslint-disable new-cap */

import { AsnProp } from '@peculiar/asn1-schema';
import { SignedData } from '@peculiar/asn1-cms';
import { Certificate } from '@peculiar/asn1-x509';

import { DnssecChainSchema } from './DnssecChainSchema.js';
import { VeraSignatureMetadataSchema } from './VeraSignatureMetadataSchema.js';

export class VeraSignatureSchema {
  @AsnProp({ type: VeraSignatureMetadataSchema })
  public metadata!: VeraSignatureMetadataSchema;

  @AsnProp({ type: DnssecChainSchema })
  public dnssecChain!: DnssecChainSchema;

  @AsnProp({ type: Certificate })
  public organisationCertificate!: Certificate;

  @AsnProp({ type: SignedData })
  public signature!: SignedData;
}
