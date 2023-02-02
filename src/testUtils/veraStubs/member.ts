import { generateRsaKeyPair } from '../../lib/utils/keys/generation.js';

export const MEMBER_NAME = 'alice';
export const MEMBER_KEY_PAIR = await generateRsaKeyPair();
