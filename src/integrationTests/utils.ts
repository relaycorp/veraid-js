import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { getRsaPublicKeyFromPrivate } from '../lib/utils/keys/generation.js';
import { derDeserializeRsaPrivateKey } from '../lib/utils/keys/serialisation.js';

const CURRENT_DIR = dirname(fileURLToPath(import.meta.url));

const ORG_PRIVATE_KEY_SERIALISED = await readFile(join(CURRENT_DIR, 'org-private-key.der'));
const ORG_PRIVATE_KEY = await derDeserializeRsaPrivateKey(ORG_PRIVATE_KEY_SERIALISED);
export const TEST_ORG_KEY_PAIR: CryptoKeyPair = {
  privateKey: ORG_PRIVATE_KEY,
  publicKey: await getRsaPublicKeyFromPrivate(ORG_PRIVATE_KEY),
};

export const TEST_ORG_NAME = 'vera.domains';
