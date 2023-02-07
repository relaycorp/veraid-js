import type { Resolver, TrustAnchor } from '@relaycorp/dnssec';

import { dnssecOnlineResolve } from '../utils/dnssec.js';

import { VeraDnssecChain } from './VeraDnssecChain.js';

export async function retrieveVeraDnssecChain(
  domainName: string,
  trustAnchors?: readonly TrustAnchor[],
  resolver?: Resolver,
): Promise<ArrayBuffer> {
  const chain = await VeraDnssecChain.retrieve(
    domainName,
    resolver ?? dnssecOnlineResolve,
    trustAnchors,
  );
  return chain.serialise();
}
