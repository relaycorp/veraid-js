import { jest } from '@jest/globals';
import { AsnParser } from '@peculiar/asn1-schema';
import { MockChain, type Resolver, RrSet, SecurityStatus } from '@relaycorp/dnssec';

import { ORG_DOMAIN, VERA_RECORD } from '../../testUtils/veraStubs.js';

import { retrieveDnssecChain } from './dnssecChainRetrieval.js';
import { DnssecChainSchema } from './DnssecChainSchema.js';
import { VeraDnssecChain } from './VeraDnssecChain.js';

const RRSET = RrSet.init(VERA_RECORD.makeQuestion(), [VERA_RECORD]);

const MOCK_CHAIN = await MockChain.generate(ORG_DOMAIN);

describe('retrieveDnssecChain', () => {
  test('TXT subdomain _vera of specified domain should be queried', async () => {
    const { resolver, trustAnchors } = MOCK_CHAIN.generateFixture(RRSET, SecurityStatus.SECURE);
    const retrieveSpy = jest.spyOn(VeraDnssecChain, 'retrieve');

    await retrieveDnssecChain(ORG_DOMAIN, resolver, trustAnchors);

    expect(retrieveSpy).toHaveBeenCalledWith(ORG_DOMAIN, resolver, trustAnchors);
  });

  test('Responses should be wrapped in an explicitly tagged SET', async () => {
    const { resolver, trustAnchors } = MOCK_CHAIN.generateFixture(RRSET, SecurityStatus.SECURE);
    const resolverSpy = jest.fn<Resolver>().mockImplementation(resolver);

    const chainSerialised = await retrieveDnssecChain(ORG_DOMAIN, resolverSpy, trustAnchors);

    const chainDeserialised = AsnParser.parse(chainSerialised, DnssecChainSchema);
    expect(chainDeserialised).toHaveLength(resolverSpy.mock.calls.length);
  });
});
