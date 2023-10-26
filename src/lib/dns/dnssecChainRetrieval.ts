import type { Resolver, TrustAnchor } from '@relaycorp/dnssec';

import { dnssecOnlineResolve } from '../utils/dnssec.js';

import { VeraidDnssecChain } from './VeraidDnssecChain.js';

export async function retrieveVeraidDnssecChain(
  domainName: string,
  trustAnchors?: readonly TrustAnchor[],
  resolver?: Resolver,
): Promise<ArrayBuffer> {
  const chain = await VeraidDnssecChain.retrieve(
    domainName,
    resolver ?? dnssecOnlineResolve,
    trustAnchors,
  );
  return chain.serialise();
}
