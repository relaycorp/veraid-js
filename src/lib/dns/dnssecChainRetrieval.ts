import { type Resolver, type TrustAnchor } from '@relaycorp/dnssec';

import { VeraDnssecChain } from './VeraDnssecChain.js';

export async function retrieveDnssecChain(
  domainName: string,
  resolver: Resolver,
  trustAnchors?: readonly TrustAnchor[],
): Promise<ArrayBuffer> {
  const chain = await VeraDnssecChain.retrieve(domainName, resolver, trustAnchors);
  return chain.serialise();
}
