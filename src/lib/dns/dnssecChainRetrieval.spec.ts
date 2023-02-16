import { jest } from '@jest/globals';
import { AsnParser } from '@peculiar/asn1-schema';
import { SecurityStatus } from '@relaycorp/dnssec';

import { MOCK_CHAIN, VERA_RRSET } from '../../testUtils/veraStubs/dnssec.js';
import { ORG_DOMAIN } from '../../testUtils/veraStubs/organisation.js';
import { DnssecChainSchema } from '../schemas/DnssecChainSchema.js';
import { dnssecOnlineResolve } from '../utils/dnssec.js';
import VeraError from '../VeraError.js';

import { retrieveVeraDnssecChain } from './dnssecChainRetrieval.js';
import { VeraDnssecChain } from './VeraDnssecChain.js';

describe('retrieveVeraDnssecChain', () => {
  test('TXT subdomain _veraid of specified domain should be queried', async () => {
    const { resolver, trustAnchors } = MOCK_CHAIN.generateFixture(
      VERA_RRSET,
      SecurityStatus.SECURE,
    );
    const retrieveSpy = jest.spyOn(VeraDnssecChain, 'retrieve');

    await retrieveVeraDnssecChain(ORG_DOMAIN, trustAnchors, resolver);

    expect(retrieveSpy).toHaveBeenCalledWith(ORG_DOMAIN, expect.anything(), trustAnchors);
  });

  test('Online DNSSEC resolver should be used by default', async () => {
    const retrieveSpy = jest.spyOn(VeraDnssecChain, 'retrieve');

    await expect(async () => retrieveVeraDnssecChain(ORG_DOMAIN)).rejects.toThrow(VeraError);

    expect(retrieveSpy).toHaveBeenCalledWith(expect.anything(), dnssecOnlineResolve, undefined);
  });

  test('Explicit DNSSEC resolver should be used if set', async () => {
    const { resolver, trustAnchors } = MOCK_CHAIN.generateFixture(
      VERA_RRSET,
      SecurityStatus.SECURE,
    );
    const retrieveSpy = jest.spyOn(VeraDnssecChain, 'retrieve');

    await retrieveVeraDnssecChain(ORG_DOMAIN, trustAnchors, resolver);

    expect(retrieveSpy).toHaveBeenCalledWith(expect.anything(), resolver, expect.anything());
  });

  test('Responses should be wrapped in an explicitly tagged SET', async () => {
    const { resolver, trustAnchors } = MOCK_CHAIN.generateFixture(
      VERA_RRSET,
      SecurityStatus.SECURE,
    );

    const chainSerialised = await retrieveVeraDnssecChain(ORG_DOMAIN, trustAnchors, resolver);

    const chainDeserialised = AsnParser.parse(chainSerialised, DnssecChainSchema);
    expect(chainDeserialised.length).toBeGreaterThan(1);
  });
});
