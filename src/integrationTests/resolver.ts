import type { Question } from '@relaycorp/dnssec';

import { dnssecOnlineResolve } from '../lib/utils/dnssec.js';

const RETRY_ATTEMPTS = 3;

async function retryUponFailure<Type>(
  wrappedFunction: () => Promise<Type>,
  attempts: number,
): Promise<Type> {
  try {
    return await wrappedFunction();
  } catch (error) {
    if (attempts <= 1) {
      throw error as Error;
    }
    return await retryUponFailure(wrappedFunction, attempts - 1);
  }
}

export async function resolveWithRetries(question: Question): Promise<Buffer> {
  return retryUponFailure(async () => dnssecOnlineResolve(question), RETRY_ATTEMPTS);
}
