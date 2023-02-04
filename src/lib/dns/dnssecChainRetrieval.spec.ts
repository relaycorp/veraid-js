import { jest } from '@jest/globals';
import { AsnParser } from '@peculiar/asn1-schema';
import { type Resolver, SecurityStatus } from '@relaycorp/dnssec';

import { MOCK_CHAIN, VERA_RRSET } from '../../testUtils/veraStubs/dnssec.js';
import { ORG_DOMAIN } from '../../testUtils/veraStubs/organisation.js';
import { DnssecChainSchema } from '../schemas/DnssecChainSchema.js';

import { retrieveDnssecChain } from './dnssecChainRetrieval.js';
import { VeraDnssecChain } from './VeraDnssecChain.js';

describe('retrieveDnssecChain', () => {
  test('TXT subdomain _vera of specified domain should be queried', async () => {
    const { resolver, trustAnchors } = MOCK_CHAIN.generateFixture(
      VERA_RRSET,
      SecurityStatus.SECURE,
    );
    const retrieveSpy = jest.spyOn(VeraDnssecChain, 'retrieve');

    await retrieveDnssecChain(ORG_DOMAIN, resolver, trustAnchors);

    expect(retrieveSpy).toHaveBeenCalledWith(ORG_DOMAIN, resolver, trustAnchors);
  });

  test('Responses should be wrapped in an explicitly tagged SET', async () => {
    const { resolver, trustAnchors } = MOCK_CHAIN.generateFixture(
      VERA_RRSET,
      SecurityStatus.SECURE,
    );
    const resolverSpy = jest.fn<Resolver>().mockImplementation(resolver);

    const chainSerialised = await retrieveDnssecChain(ORG_DOMAIN, resolverSpy, trustAnchors);

    const chainDeserialised = AsnParser.parse(chainSerialised, DnssecChainSchema);
    expect(chainDeserialised).toHaveLength(resolverSpy.mock.calls.length);
  });
});
