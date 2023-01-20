import {
  type ChainVerificationResult,
  type DatePeriod,
  dnssecLookUp,
  Message,
  Question,
  type Resolver,
  SecurityStatus,
  type TrustAnchor,
} from '@relaycorp/dnssec';
import { AsnSerializer } from '@peculiar/asn1-schema';

import { bufferToArray } from '../utils/buffers.js';
import VeraError from '../VeraError.js';
import { makeDnssecOfflineResolver } from '../utils/dnssec.js';

import { DnssecChainSchema } from './DnssecChainSchema.js';
import { type VeraRdataFields } from './VeraRdataFields.js';
import { parseTxtRdata } from './rdataSerialisation.js';

function makeQuestion(domainName: string) {
  return new Question(`_vera.${domainName}`, 'TXT');
}

export class VeraDnssecChain {
  public static async retrieve(
    domainName: string,
    resolver: Resolver,
    trustAnchors?: readonly TrustAnchor[],
  ): Promise<VeraDnssecChain> {
    const responses: ArrayBuffer[] = [];
    const veraQuery = makeQuestion(domainName);
    const finalResolver: Resolver = async (question) => {
      const response = await resolver(question);
      const responseSerialised = response instanceof Message ? response.serialise() : response;
      responses.push(bufferToArray(responseSerialised));
      return response;
    };
    let result: ChainVerificationResult;
    try {
      result = await dnssecLookUp(veraQuery, finalResolver, { trustAnchors });
    } catch (err) {
      throw new VeraError('Failed to retrieve DNSSEC chain', { cause: err });
    }

    if (result.status !== SecurityStatus.SECURE) {
      const reasons = result.reasonChain.join(', ');
      throw new VeraError(`DNSSEC chain validation failed (${result.status}): ${reasons}`);
    }

    return new VeraDnssecChain(domainName, responses);
  }

  public constructor(
    public readonly domainName: string,
    public readonly responses: readonly ArrayBuffer[],
  ) {}

  public serialise(): ArrayBuffer {
    const chain = new DnssecChainSchema(this.responses as ArrayBuffer[]);
    return AsnSerializer.serialize(chain);
  }

  public async verify(
    datePeriod: DatePeriod,
    trustAnchors?: readonly TrustAnchor[],
  ): Promise<readonly VeraRdataFields[]> {
    const resolver = makeDnssecOfflineResolver(this.responses);
    const question = makeQuestion(this.domainName);
    const dnssecOptions = { trustAnchors, dateOrPeriod: datePeriod };
    let dnssecResult: ChainVerificationResult;
    try {
      dnssecResult = await dnssecLookUp(question, resolver, dnssecOptions);
    } catch (err) {
      throw new VeraError('Failed to process DNSSEC verification offline', { cause: err });
    }
    if (dnssecResult.status !== SecurityStatus.SECURE) {
      const reasons = dnssecResult.reasonChain.join(', ');
      throw new VeraError(`Vera DNSSEC chain is invalid ${dnssecResult.status}: ${reasons}`);
    }
    return dnssecResult.result.records.map((record) => parseTxtRdata(record.dataFields as string));
  }
}
