import { createHash } from 'node:crypto';

import { arrayBufferFrom } from '../../../testUtils/buffers.js';
import { MockRsaPssProvider } from '../../../testUtils/webcrypto/MockRsaPssProvider.js';

import { generateRsaKeyPair } from './generation.js';
import { getPublicKeyDigest } from './digest.js';
import { derSerializePublicKey } from './serialisation.js';
import { RsaPssPrivateKey } from './RsaPssPrivateKey.js';

describe('getPublicKeyDigest', () => {
  test('SHA-256 digest should be returned in hex', async () => {
    const keyPair = await generateRsaKeyPair();

    const digest = await getPublicKeyDigest(keyPair.publicKey);

    expect(Buffer.from(digest)).toStrictEqual(
      createHash('sha256')
        .update(await derSerializePublicKey(keyPair.publicKey))
        .digest(),
    );
  });

  test('Public key should be extracted first if input is private key', async () => {
    const mockPublicKeySerialized = arrayBufferFrom('the public key');
    const provider = new MockRsaPssProvider();
    provider.onExportKey.mockResolvedValue(mockPublicKeySerialized);
    const privateKey = new RsaPssPrivateKey('SHA-256', provider);

    const digest = await getPublicKeyDigest(privateKey);

    expect(Buffer.from(digest)).toStrictEqual(
      createHash('sha256').update(Buffer.from(mockPublicKeySerialized)).digest(),
    );
  });
});
