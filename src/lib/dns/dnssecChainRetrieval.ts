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

import { bufferToArray } from '../utils/buffers.js';
import VeraError from '../VeraError.js';

import { DnssecChainSchema } from './DnssecChainSchema.js';

export async function retrieveDnssecChain(
  domainName: string,
  resolver: Resolver,
  trustAnchors?: readonly TrustAnchor[],
): Promise<ArrayBuffer> {
  const responses: ArrayBuffer[] = [];
  const veraQuery = new Question(`_vera.${domainName}`, 'TXT');
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

  const chain = new DnssecChainSchema(responses);
  return AsnSerializer.serialize(chain);
}
