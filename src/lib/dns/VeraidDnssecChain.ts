import {
  type ChainVerificationResult,
  dnssecLookUp,
  Message,
  Question,
  type Resolver,
  RrSet,
  SecurityStatus,
  type TrustAnchor,
} from '@relaycorp/dnssec';
import { AsnSerializer } from '@peculiar/asn1-schema';
import { subSeconds } from 'date-fns';

import { bufferToArray } from '../utils/buffers.js';
import VeraidError from '../VeraidError.js';
import { makeDnssecOfflineResolver } from '../utils/dnssec.js';
import { DatePeriod } from '../dates.js';
import { DnssecChainSchema } from '../schemas/DnssecChainSchema.js';

import type { OrganisationKeySpec } from './organisationKeys.js';
import { parseTxtRdata } from './rdataSerialisation.js';

function makeQuestion(domainName: string) {
  return new Question(`_veraid.${domainName}`, 'TXT');
}

function deserialiseResponses(responsesSerialised: readonly ArrayBuffer[]) {
  return responsesSerialised.map((responseSerialised) => {
    let response: Message;
    try {
      response = Message.deserialise(Buffer.from(responseSerialised));
    } catch (err) {
      throw new VeraidError('At least one of the response messages is malformed', { cause: err });
    }
    return response;
  });
}

function getTtlOverrideFromRelevantRdata(
  responses: Message[],
  veraQuestion: Question,
  keySpec: OrganisationKeySpec,
  serviceOid: string,
): number {
  const veraTxtResponses = responses.filter((response) => response.answersQuestion(veraQuestion));
  if (veraTxtResponses.length === 0) {
    throw new VeraidError('Chain is missing VeraId TXT response');
  }
  if (1 < veraTxtResponses.length) {
    // If DNSSEC verification were to succeed, we wouldn't know which message was used, so we have
    // to require exactly one response for the VeraId TXT RRset. Without this check, we could be
    // reading the TTL override from a bogus response.
    throw new VeraidError('Chain contains multiple VeraId TXT responses');
  }

  const veraRrset = RrSet.init(veraQuestion, veraTxtResponses[0].answers);
  const veraRdataFields = veraRrset.records.map((record) =>
    parseTxtRdata(record.dataFields as string),
  );
  const relevantRdataSet = veraRdataFields.filter(
    (fields) =>
      fields.keyAlgorithm === keySpec.keyAlgorithm &&
      fields.keyId === keySpec.keyId &&
      (fields.serviceOid === undefined || fields.serviceOid === serviceOid),
  );
  if (relevantRdataSet.length === 0) {
    throw new VeraidError('Could not find VeraId record for specified key and/or service');
  }

  const concreteRdata = relevantRdataSet.find((fields) => fields.serviceOid === serviceOid);
  const genericRdata = relevantRdataSet.find((fields) => fields.serviceOid === undefined);
  const rdata = concreteRdata ?? genericRdata;
  return rdata!.ttlOverride;
}

function getVerificationPeriod(
  responses: Message[],
  veraQuestion: Question,
  keySpec: OrganisationKeySpec,
  serviceOid: string,
  datePeriod: DatePeriod,
) {
  const ttlOverride = getTtlOverrideFromRelevantRdata(responses, veraQuestion, keySpec, serviceOid);
  const rdataPeriod = DatePeriod.init(subSeconds(datePeriod.end, ttlOverride), datePeriod.end);
  return rdataPeriod.intersect(datePeriod)!;
}

export class VeraidDnssecChain {
  public static async retrieve(
    domainName: string,
    resolver: Resolver,
    trustAnchors?: readonly TrustAnchor[],
  ): Promise<VeraidDnssecChain> {
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
      throw new VeraidError('Failed to retrieve DNSSEC chain', { cause: err });
    }

    if (result.status !== SecurityStatus.SECURE) {
      const reasons = result.reasonChain.join(', ');
      throw new VeraidError(`DNSSEC chain validation failed (${result.status}): ${reasons}`);
    }

    return new VeraidDnssecChain(domainName, responses);
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
    keySpec: OrganisationKeySpec,
    serviceOid: string,
    datePeriod: DatePeriod,
    trustAnchors?: readonly TrustAnchor[],
  ): Promise<void> {
    const responses = deserialiseResponses(this.responses);
    const resolver = makeDnssecOfflineResolver(responses);
    const veraQuestion = makeQuestion(this.domainName);
    const finalPeriod = getVerificationPeriod(
      responses,
      veraQuestion,
      keySpec,
      serviceOid,
      datePeriod,
    );

    let dnssecResult: ChainVerificationResult;
    try {
      dnssecResult = await dnssecLookUp(veraQuestion, resolver, {
        trustAnchors,
        dateOrPeriod: finalPeriod,
      });
    } catch (err) {
      throw new VeraidError('Failed to process DNSSEC verification offline', { cause: err });
    }

    if (dnssecResult.status !== SecurityStatus.SECURE) {
      const reasons = dnssecResult.reasonChain.join(', ');
      throw new VeraidError(`VeraId DNSSEC chain is ${dnssecResult.status}: ${reasons}`);
    }
  }
}
