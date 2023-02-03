import { type HashingAlgorithm } from '../algorithms.js';

export interface SignatureOptions {
  readonly hashingAlgorithmName: HashingAlgorithm;
  readonly encapsulatePlaintext: boolean;
}
