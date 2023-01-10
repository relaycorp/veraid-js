import { AsnSerializer } from '@peculiar/asn1-schema';
import {
  type ChainVerificationResult,
  dnssecLookUp,
  Message,
  Question,
  type Resolver,
  SecurityStatus,
  type TrustAnchor,
} from '@relaycorp/dnssec';

import { dnssecResolve } from '../utils/dnssec.js';
import { bufferToArray } from '../utils/buffers.js';
import VeraError from '../VeraError.js';

import { DnssecChain } from './DnssecChain.js';

export async function retrieveDnssecChain(
  domainName: string,
  trustAnchors?: readonly TrustAnchor[],
  resolver: Resolver = dnssecResolve,
): Promise<ArrayBuffer> {
  const responses: ArrayBuffer[] = [];
  const veraQuery = new Question(`_vera.${domainName}`, 'TXT');
  const finalResolver: Resolver = async (question) => {
    const response = await resolver(question);
    const responseSerialised =
      response instanceof Message ? response.serialise() : bufferToArray(response);
    responses.push(responseSerialised);
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

  const chain = new DnssecChain(responses);
  return AsnSerializer.serialize(chain);
}
